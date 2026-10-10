import { useEffect, useState, type FormEvent } from "react";
import { CircleMarker, MapContainer, Popup, TileLayer, ZoomControl } from "react-leaflet";
import { AlertTriangle, LocateFixed, MapPin, Navigation, Phone, Search, ShieldCheck } from "lucide-react";
import { api, post } from "./api";
import type { LatLngExpression } from "leaflet";

interface Place {
  id: string; name: string; category: "cybercrime" | "police" | "emergency"; address: string;
  phone: string | null; phone_verified: boolean; official_source: string | null; source_url: string;
  source_name: string; verification_date: string; latitude: number; longitude: number;
  directions_url: string; distance_km: number;
}
interface Contact { name: string; number: string; purpose: string; source_url: string; source_name: string; retrieved_at: string }
interface SearchResult {
  location: string; center: { latitude: number; longitude: number } | null;
  results: Place[]; official_contacts: Contact[]; retrieved_at: string; attribution: string;
  cybercrime_found?: boolean; note?: string | null;
}

const INITIAL_CENTER: LatLngExpression = [22.5, 79];

export default function Assistance() {
  const [location, setLocation] = useState("");
  const [result, setResult] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [officialContacts, setOfficialContacts] = useState<Contact[]>([]);
  const [contactsRetrievedAt, setContactsRetrievedAt] = useState("");
  const [contactsLoading, setContactsLoading] = useState(true);
  const [contactsError, setContactsError] = useState("");
  const [filters, setFilters] = useState({ cybercrime: true, police: true, emergency: true });

  useEffect(() => {
    void api<{ official_contacts: Contact[]; retrieved_at: string }>("/api/assistance/contacts")
      .then((data) => { setOfficialContacts(data.official_contacts); setContactsRetrievedAt(data.retrieved_at); })
      .catch((issue) => setContactsError(issue instanceof Error ? issue.message : "Official contacts are unavailable."))
      .finally(() => setContactsLoading(false));
  }, []);

  async function search(payload: { location_query?: string; latitude?: number; longitude?: number }) {
    setLoading(true); setError("");
    try {
      setResult(await post<SearchResult>("/api/assistance/search", { ...payload, radius_m: 20000, categories: ["cybercrime", "police", "emergency"] }));
    } catch (issue) {
      setResult(null);
      setError(issue instanceof Error ? issue.message : "Location search failed. Try again or use the official national contacts.");
    } finally { setLoading(false); }
  }

  function findNearby() {
    setError("");
    if (!navigator.geolocation) { setError("This browser does not provide geolocation. Search by city, locality or PIN code instead."); return; }
    setLoading(true);
    navigator.geolocation.getCurrentPosition(
      (position) => { void search({ latitude: position.coords.latitude, longitude: position.coords.longitude }); },
      (issue) => {
        setLoading(false);
        setError(issue.code === issue.PERMISSION_DENIED
          ? "Location access was denied. Search by city, locality or PIN code instead. Your coordinates were not stored."
          : "Your location is unavailable. Search by city, locality or PIN code instead.");
      },
      { enableHighAccuracy: false, timeout: 12000, maximumAge: 60000 },
    );
  }

  async function submitSearch(event: FormEvent) {
    event.preventDefault();
    if (!location.trim()) { setError("Enter a city, locality or PIN code."); return; }
    await search({ location_query: location.trim() });
  }

  const visiblePlaces = (result?.results ?? []).filter((place) => filters[place.category]);
  const contacts = result?.official_contacts ?? officialContacts;
  const contactsTimestamp = result?.retrieved_at ?? contactsRetrievedAt;
  const mapCenter: LatLngExpression = result?.center ? [result.center.latitude, result.center.longitude] : INITIAL_CENTER;
  const mapKey = result?.center ? `${result.center.latitude},${result.center.longitude}` : "india";

  return <div className="page-stack assistance-page">
    <div className="page-heading"><div><span className="eyebrow">LOCAL SUPPORT</span><h1>Cyber help near me</h1><p>Find listed police resources, then verify details through the linked source before travelling.</p></div><span className="live-tag"><span /> Open data lookup</span></div>
    <form className="location-search" onSubmit={submitSearch}>
      <label className="sr-only" htmlFor="place-query">Search city, locality or PIN code</label>
      <MapPin size={17} /><input id="place-query" value={location} onChange={(event) => setLocation(event.target.value)} maxLength={160} placeholder="City, locality or PIN code" />
      <button className="button button--primary" type="submit" disabled={loading}><Search size={16} /> Search</button>
      <button className="button button--secondary" type="button" onClick={findNearby} disabled={loading}><LocateFixed size={16} /> Find near me</button>
    </form>
    <div className="filter-row" aria-label="Filter assistance types">
      {(["cybercrime", "police", "emergency"] as const).map((key) => <label className="filter-check" key={key}><input type="checkbox" checked={filters[key]} onChange={(event) => setFilters((old) => ({ ...old, [key]: event.target.checked }))} />{key === "cybercrime" ? "Cybercrime services" : key === "police" ? "Police stations" : "Emergency services + national contacts"}</label>)}
    </div>
    {error && <div className="notice notice--error" role="alert"><AlertTriangle size={18} />{error}</div>}
    {loading && <div className="notice"><span className="spinner" /> Searching OpenStreetMap data…</div>}
    {result?.note && <div className="notice notice--warning" role="status"><AlertTriangle size={17} />{result.note}</div>}
    <div className="map-frame">
      <MapContainer key={mapKey} center={mapCenter} zoom={result?.center ? 12 : 4} scrollWheelZoom zoomControl={false} className="help-map">
        <ZoomControl position="bottomright" />
        <TileLayer attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap contributors</a>' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        {visiblePlaces.map((place) => <CircleMarker key={place.id} center={[place.latitude, place.longitude]} radius={8} pathOptions={{ color: place.category === "cybercrime" ? "#58e0c1" : place.category === "emergency" ? "#ff737d" : "#ffb66d", fillOpacity: 0.9 }}>
          <Popup><strong>{place.name}</strong><br />{place.category === "cybercrime" ? "Cybercrime service (OSM tag)" : place.category === "emergency" ? "General emergency service" : "Police station"}<br />{place.address}</Popup>
        </CircleMarker>)}
      </MapContainer>
      {!result?.center && !loading && <div className="map-hint">Choose “Find near me” or search a location to load nearby places.</div>}
    </div>
    <div className="map-attribution">{result?.attribution ?? "Map tiles © OpenStreetMap contributors."} {result && <> Retrieved {new Date(result.retrieved_at).toLocaleString()}.</>}</div>
    {result && <section className="place-section">
      <div className="section-title"><h2>Listed assistance</h2><span>{visiblePlaces.length} places near {result.location.split(",")[0]}</span></div>
      {visiblePlaces.length ? <div className="place-list">{visiblePlaces.map((place) => <article className="place-row" key={place.id}>
        <div className="place-icon"><ShieldCheck size={18} /></div>
        <div className="place-info"><div className="place-title"><strong>{place.name}</strong><span className={`type-tag type-tag--${place.category}`}>{place.category === "cybercrime" ? "Cybercrime" : place.category === "emergency" ? "Emergency service" : "Police"}</span></div>
          <p>{place.address}</p><div className="place-meta"><span>{place.distance_km} km away</span><span>Listed {new Date(place.verification_date).toLocaleDateString()}</span></div>
          <p className="unverified"><AlertTriangle size={13} /> OpenStreetMap record; contact and services not independently verified.</p>
        </div>
        <div className="place-actions">{place.phone ? <a className="button button--secondary button--small" href={`tel:${place.phone}`}><Phone size={14} />{place.phone}</a> : <span className="phone-missing">No public phone listed</span>}
          <a className="button button--secondary button--small" href={place.directions_url} target="_blank" rel="noreferrer"><Navigation size={14} /> Directions</a>
          <a className="source-link" href={place.official_source ?? place.source_url} target="_blank" rel="noreferrer">{place.official_source ? "Listed website" : "OpenStreetMap source"}</a>
        </div>
      </article>)}</div> : <div className="empty-state"><MapPin size={22} /><strong>No listed places found</strong><p>Try a nearby city or expand your search area. National contacts are still available below.</p></div>}
    </section>}
    <section className="national-support">
      <div className="section-title"><h2>India-wide contacts</h2><span>Official reporting and emergency channels</span></div>
      {contactsLoading && <div className="loading-line"><span className="spinner" />Loading official contacts…</div>}
      {contactsError && !contacts.length && <div className="notice notice--error" role="alert">{contactsError} Use the National Cyber Crime Reporting Portal link below for current reporting guidance.</div>}
      {!!contacts.length && <div className="contact-grid">{contacts.map((contact) => <article className="national-contact" key={contact.number}><span className="contact-number">{contact.number}</span><div><strong>{contact.name}</strong><p>{contact.purpose}</p><a className="button button--secondary button--small contact-call" href={`tel:${contact.number}`}>Call {contact.number}</a>{" "}<a href={contact.source_url} target="_blank" rel="noreferrer">{contact.source_name} <span aria-hidden="true">↗</span></a></div></article>)}</div>}
      {contactsTimestamp && <p className="source-note">Official contact information retrieved {new Date(contactsTimestamp).toLocaleString()}.</p>}
      {!contacts.some((contact) => contact.number === "1930") && <article className="national-contact"><span className="contact-number">1930</span><div><strong>Cyber Crime Helpline</strong><p>Report online financial cyber fraud promptly.</p><a className="button button--secondary button--small contact-call" href="tel:1930">Call 1930</a></div></article>}
      <a className="portal-link" href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">National Cyber Crime Reporting Portal: https://cybercrime.gov.in/ <span aria-hidden="true">↗</span></a>
    </section>
    <p className="source-note">{result?.attribution ?? "Nearby place search uses OpenStreetMap. Phone numbers may be absent and listings are not independently verified."} Search timestamp is displayed with results. This tool does not contact any station or file a complaint.</p>
  </div>;
}