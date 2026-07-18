from flask import Flask, jsonify, request, render_template
import requests, re, socket

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError, ASNRegistryError
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

app = Flask(__name__)

HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "keep-alive",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
}

IP_API_URL    = "http://ip-api.com/json/{}"
IP_API_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
IP_API_BATCH  = "http://ip-api.com/batch"

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── IP / ISP geo lookup ───────────────────────────────────────────────────────
@app.route("/api/lookup")
def lookup():
    target = request.args.get("ip", "").strip()
    url = IP_API_URL.format(target) if target else IP_API_URL.format("")
    try:
        resp = requests.get(url, params={"fields": IP_API_FIELDS}, timeout=6)
        data = resp.json()
    except requests.RequestException as e:
        return jsonify({"status": "fail", "message": str(e)}), 502

    if data.get("status") != "success":
        return jsonify({"status": "fail", "message": data.get("message", "lookup failed")}), 400
    return jsonify(data)


# ── OSINT: WHOIS / RDAP + Reverse DNS + ASN ───────────────────────────────────
@app.route("/api/osint")
def osint():
    target = request.args.get("ip", "").strip()
    if not target:
        return jsonify({"status": "fail", "message": "ip required"}), 400
    if not IPV4_RE.match(target):
        # Try to resolve a domain to an IP first (best-effort)
        try:
            target = socket.gethostbyname(target)
        except socket.gaierror:
            return jsonify({"status": "fail", "message": "invalid ip/hostname"}), 400

    result = {"status": "ok", "query": target}

    # ── Reverse DNS (PTR) ──
    try:
        host, aliases, _ = socket.gethostbyaddr(target)
        result["reverse_dns"] = host
        result["reverse_dns_aliases"] = aliases or []
    except (socket.herror, socket.gaierror):
        result["reverse_dns"] = None
        result["reverse_dns_aliases"] = []
    except Exception as e:
        result["reverse_dns"] = None
        result["reverse_dns_error"] = str(e)

    # ── RDAP (WHOIS + ASN) via ipwhois ──
    if not IPWHOIS_AVAILABLE:
        result["rdap_error"] = "ipwhois package not installed on server (pip install ipwhois)"
        return jsonify(result)

    try:
        obj = IPWhois(target)
        rdap = obj.lookup_rdap(depth=1, rate_limit_timeout=10)

        result["asn"] = rdap.get("asn")
        result["asn_cidr"] = rdap.get("asn_cidr")
        result["asn_country_code"] = rdap.get("asn_country_code")
        result["asn_registry"] = rdap.get("asn_registry")
        result["asn_description"] = rdap.get("asn_description")
        result["asn_date"] = rdap.get("asn_date")

        network = rdap.get("network") or {}
        result["network_name"] = network.get("name")
        result["network_handle"] = network.get("handle")
        result["network_range"] = network.get("cidr")
        result["network_start"] = network.get("start_address")
        result["network_end"] = network.get("end_address")
        result["network_type"] = network.get("type")
        result["network_country"] = network.get("country")

        # Contacts / abuse info from RDAP entities
        contacts = []
        objects = rdap.get("objects") or {}
        for handle, obj_data in objects.items():
            contact = obj_data.get("contact") or {}
            emails = [e.get("value") for e in (contact.get("email") or []) if e.get("value")]
            contacts.append({
                "handle": handle,
                "name": contact.get("name"),
                "roles": obj_data.get("roles", []),
                "email": emails,
            })
        result["contacts"] = contacts

    except IPDefinedError:
        result["rdap_error"] = "private/reserved IP range — no public RDAP record"
    except ASNRegistryError as e:
        result["rdap_error"] = "ASN registry lookup failed: " + str(e)
    except Exception as e:
        result["rdap_error"] = str(e)

    return jsonify(result)


# ── Insecam: list countries ───────────────────────────────────────────────────
@app.route("/api/cam/countries")
def cam_countries():
    try:
        resp = requests.get("http://www.insecam.org/en/jsoncountries/",
                            headers=HEADERS, timeout=10)
        data = resp.json()
        countries = [
            {"code": k, "name": v["country"], "count": v["count"]}
            for k, v in data["countries"].items()
            if v.get("count", 0) > 0
        ]
        countries.sort(key=lambda x: -x["count"])
        return jsonify({"status": "ok", "countries": countries})
    except Exception as e:
        return jsonify({"status": "fail", "message": str(e)}), 502


# ── Insecam: scrape camera IPs for a country, geolocate & return ──────────────
@app.route("/api/cam/scan")
def cam_scan():
    country = request.args.get("country", "").strip().upper()
    max_pages = int(request.args.get("pages", 3))
    if max_pages >= 999:
        max_pages = 9999  # effectively unlimited — scan all pages
    if not country:
        return jsonify({"status": "fail", "message": "country code required"}), 400

    all_ips = []
    try:
        res = requests.get(f"http://www.insecam.org/en/bycountry/{country}",
                           headers=HEADERS, timeout=10)
        pages_found = re.findall(r'pagenavigator\("\?page=", (\d+)', res.text)
        last_page = int(pages_found[0]) if pages_found else 1
        pages_to_scan = min(last_page, max_pages)

        for page in range(pages_to_scan):
            res = requests.get(
                f"http://www.insecam.org/en/bycountry/{country}/?page={page}",
                headers=HEADERS, timeout=10
            )
            found = re.findall(r"http://(\d+\.\d+\.\d+\.\d+:\d+)", res.text)
            all_ips.extend(found)

    except Exception as e:
        return jsonify({"status": "fail", "message": str(e)}), 502

    # De-duplicate, keep just the base IP for geo lookup
    unique_ips = list(dict.fromkeys(ip.split(":")[0] for ip in all_ips))[:100]
    full_urls  = {ip.split(":")[0]: f"http://{ip}" for ip in all_ips}

    if not unique_ips:
        return jsonify({"status": "ok", "cameras": []})

    # Batch geolocate (ip-api allows up to 100 per batch)
    try:
        batch_resp = requests.post(
            IP_API_BATCH,
            json=[{"query": ip, "fields": IP_API_FIELDS} for ip in unique_ips],
            timeout=15
        )
        geo_list = batch_resp.json()
    except Exception as e:
        return jsonify({"status": "fail", "message": "geo batch failed: " + str(e)}), 502

    cameras = []
    for g in geo_list:
        if g.get("status") == "success":
            g["stream_url"] = full_urls.get(g["query"], "")
            cameras.append(g)

    return jsonify({"status": "ok", "cameras": cameras, "pages_scanned": pages_to_scan})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
