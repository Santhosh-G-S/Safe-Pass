// Read Google Maps API key from data attribute
const mapsKey = document.getElementById("maps-config").dataset.mapsKey;

// Dynamically load Google Maps API script
const script = document.createElement("script");
script.src = `https://maps.googleapis.com/maps/api/js?key=${mapsKey}&libraries=marker&callback=initMap&v=beta`;
script.async = true;
script.defer = true;
document.head.appendChild(script);

// Global variables
let map, clusterer, markers = [], infoWindow;

window.initMap = async function () {
    console.log('Initializing map with AdvancedMarkerElement...');

    const isMyReports = window.location.pathname === '/myreport';
    const apiUrl = isMyReports ? '/api/v1/reports/me' : '/api/v1/reports';
    const limit = 20;
    let currentPage = 1;
    let reportsData = [];

    const { AdvancedMarkerElement, PinElement } = await google.maps.importLibrary("marker");

    map = new google.maps.Map(document.getElementById('map'), {
        center: { lat: 20.5937, lng: 78.9629 },
        zoom: 5,
        mapId: 'DEMO_MAP_ID',
        mapTypeControl: true,
        streetViewControl: false,
        fullscreenControl: true
    });

    infoWindow = new google.maps.InfoWindow();

    // DOM elements
    const detailTitle   = document.getElementById('detailTitle');
    const detailType    = document.getElementById('detailType');
    const detailAddress = document.getElementById('detailAddress');
    const detailDesc    = document.getElementById('detailDesc');
    const detailWhen    = document.getElementById('detailWhen');
    const noSelection   = document.getElementById('noSelection');
    const filterInput   = document.getElementById('filterInput');
    const typeFilter    = document.getElementById('typeFilter');

    // ── Helpers ──────────────────────────────────────────────

    function getShortAddress(fullAddress) {
        return fullAddress || 'Location not available';
    }

    function getAreaName(fullAddress) {
        if (!fullAddress) return 'Unknown Location';
        const parts = fullAddress.split(',').map(p => p.trim());
        if (parts.length >= 3) return parts.slice(0, 3).join(', ');
        if (parts.length >= 2) return parts.slice(0, 2).join(', ');
        return parts[0] || 'Unknown Location';
    }

    function getMarkerColor(incidentType) {
        const colors = {
            theft: '#DC3545',
            harassment: '#FD7E14',
            hazard: '#FFC107',
            other: '#6C757D'
        };
        return colors[incidentType] || colors.other;
    }

    function createInfoWindowContent(r) {
        const shortDesc = r.description
            ? (r.description.length > 120 ? r.description.substring(0, 120) + '...' : r.description)
            : '';
        const areaName = getAreaName(r.address);

        return `<div style="max-width:250px; padding:8px; color:#000;">
            <strong style="font-size:14px;">Report #${r.reportNumber}</strong><br/>
            <span style="color:#666; font-size:12px;">${r.incident_type || 'Report'} • ${areaName}</span><br/>
            <small style="color:#888;">${r.date || ''} ${r.time || ''}</small>
            <div style="margin-top:6px; font-size:13px;">${shortDesc}</div>
            <div style="margin-top:8px;">
                <a href="#" class="viewDetails" data-reportid="${r.id}"
                   style="color:#0d6efd; text-decoration:none;">View full details →</a>
            </div>
        </div>`;
    }

    // ── Details panel ─────────────────────────────────────────

    function clearDetails() {
        detailTitle.textContent = 'Select a marker';
        detailType.textContent = '';
        detailAddress.textContent = '';
        detailDesc.textContent = '';
        detailWhen.textContent = '';
        noSelection.style.display = 'block';
    }

    function showDetails(report) {
        noSelection.style.display = 'none';
        detailTitle.textContent = 'Report #' + report.reportNumber;
        detailType.innerHTML = '<strong>Type:</strong> ' + (report.incident_type || 'Unknown');
        const shortAddr = getShortAddress(report.address);
        detailAddress.innerHTML = shortAddr
            ? `<small class="text-muted">${shortAddr}</small>` : '';
        detailDesc.textContent = report.description || '';
        const reportedTime = report.created_at
            ? new Date(report.created_at).toLocaleString() : 'N/A';
        detailWhen.textContent =
            `Incident: ${report.date || 'N/A'} at ${report.time || 'N/A'} • Reported: ${reportedTime}`;

        if (report.latitude && report.longitude) {
            map.panTo({ lat: report.latitude, lng: report.longitude });
            map.setZoom(Math.max(map.getZoom(), 15));
        }
    }

    // ── Markers & clustering ──────────────────────────────────

    function plotReports(data) {
        console.log('Plotting', data.length, 'reports');

        markers.forEach(m => m.map = null);
        markers = [];
        if (clusterer) clusterer.clearMarkers();

        if (!Array.isArray(data) || data.length === 0) {
            clearDetails();
            return;
        }

        data.forEach(r => {
            if (!r.latitude || !r.longitude) return;
            const lat = parseFloat(r.latitude);
            const lng = parseFloat(r.longitude);
            if (isNaN(lat) || isNaN(lng)) return;

            const pinElement = new PinElement({
                background: getMarkerColor(r.incident_type),
                borderColor: '#FFFFFF',
                glyphColor: '#FFFFFF',
                scale: 1.2
            });

            const marker = new AdvancedMarkerElement({
                map,
                position: { lat, lng },
                title: `Report #${r.reportNumber} - ${r.incident_type || 'Report'}`,
                content: pinElement.element
            });

            marker.addListener('click', function () {
                infoWindow.setContent(createInfoWindowContent(r));
                infoWindow.open(map, marker);

                setTimeout(() => {
                    const link = document.querySelector(`.viewDetails[data-reportid="${r.id}"]`);
                    if (link) {
                        link.onclick = function (e) {
                            e.preventDefault();
                            showDetails(r);
                            infoWindow.close();
                        };
                    }
                }, 100);
            });

            markers.push(marker);
        });

        if (typeof markerClusterer !== 'undefined' && markerClusterer.MarkerClusterer) {
            clusterer = new markerClusterer.MarkerClusterer({ map, markers });
        }

        if (markers.length > 0) {
            const bounds = new google.maps.LatLngBounds();
            markers.forEach(m => bounds.extend(m.position));
            map.fitBounds(bounds);

            if (markers.length === 1) {
                google.maps.event.addListenerOnce(map, 'bounds_changed', function () {
                    if (map.getZoom() > 16) map.setZoom(16);
                });
            }
        }
    }

    // ── Filtering ─────────────────────────────────────────────

    function applyFiltersAndPlot() {
        const q = filterInput.value.trim().toLowerCase();
        const typeQ = typeFilter.value;

        const filtered = reportsData.filter(r => {
            if (typeQ && r.incident_type !== typeQ) return false;
            if (q) {
                return (r.description && r.description.toLowerCase().includes(q)) ||
                       (r.address     && r.address.toLowerCase().includes(q))     ||
                       (r.incident_type && r.incident_type.toLowerCase().includes(q));
            }
            return true;
        });

        plotReports(filtered);
    }

    // ── Pagination & loading ──────────────────────────────────

    async function loadReports(page = 1) {
        const res  = await fetch(`${apiUrl}?page=${page}&limit=${limit}`);
        const json = await res.json();

        reportsData = json.data.reports;
        reportsData.forEach((report, index) => {
            report.reportNumber = ((page - 1) * limit) + index + 1;
        });

        const pagination = json.data.pagination;
        if (pagination) {
            document.getElementById('pageInfo').textContent =
                `Page ${pagination.page} of ${pagination.pages} (${pagination.total} reports)`;
            document.getElementById('prevBtn').disabled = !pagination.has_prev;
            document.getElementById('nextBtn').disabled = !pagination.has_next;
            currentPage = pagination.page;
        }

        applyFiltersAndPlot();
    }

    // ── Event listeners ───────────────────────────────────────

    filterInput.addEventListener('input', applyFiltersAndPlot);
    typeFilter.addEventListener('change', applyFiltersAndPlot);
    document.getElementById('reloadBtn').addEventListener('click', () => loadReports(currentPage));
    document.getElementById('prevBtn').addEventListener('click', () => loadReports(currentPage - 1));
    document.getElementById('nextBtn').addEventListener('click', () => loadReports(currentPage + 1));

    // ── Init ──────────────────────────────────────────────────

    clearDetails();
    await loadReports(1);
};

window.gm_authFailure = function () {
    alert('Google Maps API authentication failed. Please check your API key.');
};
