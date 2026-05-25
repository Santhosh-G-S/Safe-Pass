// Read Google Maps API key from data attribute
const mapsKey = document.getElementById("maps-config").dataset.mapsKey;

// Dynamically load Google Maps API
const script = document.createElement("script");
script.src = `https://maps.googleapis.com/maps/api/js?key=${mapsKey}&libraries=places,geocoding,marker&callback=initMap&v=beta`;
script.async = true;
script.defer = true;
document.head.appendChild(script);

// Global variables
let map, marker, geocoder;

window.initMap = async function () {
    console.log('Initializing map with AdvancedMarkerElement...');

    // DOM elements
    const latInput         = document.getElementById('lat');
    const lngInput         = document.getElementById('lng');
    const addressInput     = document.getElementById('address');
    const locationDisplay  = document.getElementById('locationDisplay');
    const submitBtn        = document.getElementById('submitBtn');
    const btnText          = document.getElementById('btnText');
    const searchBox        = document.getElementById('searchBox');
    const searchResults    = document.getElementById('searchResults');

    const { AdvancedMarkerElement, PinElement } = await google.maps.importLibrary("marker");

    // ── Map init ──────────────────────────────────────────────

    map = new google.maps.Map(document.getElementById('map'), {
        center: { lat: 20.5937, lng: 78.9629 },
        zoom: 5,
        mapId: 'DEMO_MAP_ID',
        mapTypeControl: true,
        streetViewControl: true,
        fullscreenControl: true
    });

    // ── Geocoder ──────────────────────────────────────────────

    try {
        const { Geocoder } = await google.maps.importLibrary("geocoding");
        geocoder = new Geocoder();
        console.log('✓ Geocoder initialized');
    } catch (error) {
        console.warn('Geocoder not available:', error);
    }

    // ── User geolocation ──────────────────────────────────────

    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
            function (pos) {
                map.setCenter({ lat: pos.coords.latitude, lng: pos.coords.longitude });
                map.setZoom(15);
            },
            function () {},
            { timeout: 5000 }
        );
    }

    // ── Marker placement ──────────────────────────────────────

    map.addListener('click', function (e) {
        placeMarker(e.latLng.lat(), e.latLng.lng());
    });

    function placeMarker(lat, lng) {
        if (marker) marker.map = null;

        const pinElement = new PinElement({
            background: '#DC3545',
            borderColor: '#FFFFFF',
            glyphColor: '#FFFFFF',
            scale: 1.3
        });

        marker = new AdvancedMarkerElement({
            map,
            position: { lat, lng },
            content: pinElement.element,
            gmpDraggable: true,
            title: 'Incident Location'
        });

        marker.addListener('dragend', function (e) {
            updateLocation(e.latLng.lat, e.latLng.lng);
        });

        updateLocation(lat, lng);
    }

    // ── Location update & reverse geocoding ───────────────────

    async function updateLocation(lat, lng) {
        latInput.value = lat;
        lngInput.value = lng;
        locationDisplay.innerHTML = '<small class="text-muted">📍 Getting address...</small>';

        const coordAddr = `Lat: ${lat.toFixed(5)}, Lng: ${lng.toFixed(5)}`;
        addressInput.value = coordAddr;
        submitBtn.disabled = false;
        btnText.textContent = 'Submit Report';

        if (!geocoder) {
            locationDisplay.innerHTML =
                `<strong class="text-success">✓ Location Selected</strong><br>
                 <small>${coordAddr}</small>`;
            return;
        }

        try {
            const response = await geocoder.geocode({ location: { lat, lng } });

            if (response.results && response.results.length > 0) {
                const fullAddr = response.results[0].formatted_address;
                addressInput.value = fullAddr;
                locationDisplay.innerHTML =
                    `<strong class="text-success">✓ Location Selected</strong><br>
                     <small>${fullAddr}</small>`;
            } else {
                locationDisplay.innerHTML =
                    `<strong class="text-success">✓ Location Selected</strong><br>
                     <small class="text-muted">${coordAddr}</small>`;
            }
        } catch (error) {
            console.log('Geocoding error:', error.code, error.message);

            if (error.code === 'REQUEST_DENIED') {
                locationDisplay.innerHTML =
                    `<strong class="text-warning">⚠ Geocoding API Authorization Issue</strong><br>
                     <small>Using coordinates: ${coordAddr}</small><br>
                     <small class="text-info">Check: Google Cloud Console → API Key → Add Geocoding API</small>`;
            } else if (error.code === 'OVER_QUERY_LIMIT') {
                locationDisplay.innerHTML =
                    `<strong class="text-warning">⚠ API Quota Exceeded</strong><br>
                     <small>Using coordinates: ${coordAddr}</small>`;
            } else {
                locationDisplay.innerHTML =
                    `<strong class="text-success">✓ Location Selected</strong><br>
                     <small>${coordAddr}</small>`;
            }
        }
    }

    // ── Search ────────────────────────────────────────────────

    let searchTimeout;

    searchBox.addEventListener('input', function () {
        clearTimeout(searchTimeout);
        const query = searchBox.value.trim();

        if (query.length < 3) {
            searchResults.style.display = 'none';
            return;
        }

        searchTimeout = setTimeout(() => performSearch(query), 500);
    });

    async function performSearch(query) {
        searchResults.innerHTML = '<div class="list-group-item">Searching...</div>';
        searchResults.style.display = 'block';

        try {
            const { Place } = await google.maps.importLibrary("places");

            const { places } = await Place.searchByText({
                textQuery: query + ' India',
                fields: ['displayName', 'location', 'formattedAddress'],
                locationBias: map.getCenter(),
                maxResultCount: 5
            });

            if (!places || places.length === 0) {
                searchResults.innerHTML =
                    '<div class="list-group-item">No results found. Try city names, landmarks, or addresses.</div>';
                return;
            }

            searchResults.innerHTML = '';

            places.forEach(place => {
                const item = document.createElement('a');
                item.href = '#';
                item.className = 'list-group-item list-group-item-action';
                item.innerHTML =
                    `<div><strong>${place.displayName || 'Unknown'}</strong></div>
                     <small class="text-muted">${place.formattedAddress || ''}</small>`;

                item.onclick = function (e) {
                    e.preventDefault();
                    if (place.location) {
                        const lat = place.location.lat();
                        const lng = place.location.lng();
                        map.setCenter({ lat, lng });
                        map.setZoom(17);
                        placeMarker(lat, lng);
                        searchResults.style.display = 'none';
                        searchBox.value = '';
                    }
                };

                searchResults.appendChild(item);
            });

        } catch (error) {
            console.error('Search error:', error);
            searchResults.innerHTML =
                '<div class="list-group-item text-muted">Search not available. Click on map instead.</div>';
        }
    }

    // Hide search results on outside click
    document.addEventListener('click', function (e) {
        if (!searchBox.contains(e.target) && !searchResults.contains(e.target)) {
            searchResults.style.display = 'none';
        }
    });

    // ── Default date & time ───────────────────────────────────

    const now = new Date();
    const pad = n => String(n).padStart(2, '0');
    document.getElementById('date').value =
        `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
    document.getElementById('time').value =
        `${pad(now.getHours())}:${pad(now.getMinutes())}`;

    // ── Form submission ───────────────────────────────────────

    document.getElementById('reportForm').addEventListener('submit', async function (e) {
        e.preventDefault();

        if (!latInput.value || !lngInput.value) {
            alert('Please select a location on the map first!');
            return;
        }

        const data = {
            latitude:      latInput.value,
            longitude:     lngInput.value,
            address:       addressInput.value,
            incident_type: document.querySelector('select[name="incident_type"]').value,
            description:   document.querySelector('textarea[name="description"]').value,
            date:          document.getElementById('date').value,
            time:          document.getElementById('time').value
        };

        try {
            const response = await fetch('/api/v1/reports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (response.ok && result.success) {
                alert('Report submitted successfully!');
                window.location.reload();
            } else {
                alert(result.error.message || 'Failed to submit report');
            }
        } catch (err) {
            alert('Network error. Please try again.');
        }
    });

    console.log('Map ready with AdvancedMarkerElement!');
};

window.gm_authFailure = function () {
    alert('Google Maps API authentication failed.');
};
