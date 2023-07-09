const packetList = document.getElementById("packet-cards");
let packets = [];

function makeRequest() {
    let endpoint = `/data_stream?last_packet_id=${lastPacketId}`;
    fetch(endpoint)
        .then(function (response) {
            if (response.ok) {
                return response.json();
            }
            throw new Error('Network response was not OK.');
        })
        .then(function (data) {
            updatePacketCards(data);
        })
        .catch(function (error) {
            console.log('Request failed:', error);
        });

}

setInterval(makeRequest, 500);

function updateUI(data) {
    data.forEach(packet => {

    })
}