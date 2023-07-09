const packetList = document.getElementById("packet-cards");
let packets = [];

let lastPacketId = 0;

let sortByAppProtocol = "ALL";
let sortByTransProtocol = "ALL";
let keyWord = null;

function setSortByApplicationProtocol() {
    sortByAppProtocol = document.getElementById("app_protocol").value
    document.getElementById('packet-cards').innerHTML = "";
    packets.forEach(packet => {
        addPacketCard(packet)
    });
}

function setSortByTransportProtocol() {
    sortByTransProtocol = document.getElementById("trans_protocol").value
}

const eventSource = new EventSource("/data_stream");
eventSource.onmessage = function(event) {
    updatePacketCards(event.data.json())
}
// function makeRequest() {
//     let endpoint = `/data_stream?last_packet_id=${lastPacketId}`;
//     fetch(endpoint)
//         .then(function (response) {
//             if (response.ok) {
//                 return response.json();
//             }
//             throw new Error('Network response was not OK.');
//         })
//         .then(function (data) {
//             updatePacketCards(data);
//         })
//         .catch(function (error) {
//             console.log('Request failed:', error);
//         });
//
// }
//
// setInterval(makeRequest, 500)


function updatePacketCards(data) {
    data.forEach(packet => {
        if (packet.id > lastPacketId) {
            addPacketCard(packet);
            packets.push(packet);
            lastPacketId = packet.id
        }
    });

    const cards = document.querySelectorAll('.card-columns .card');
    cards.forEach(function (card) {
        card.addEventListener('click', function () {
            const cardId = this.querySelector('.card-id').textContent;
            renderDetails(cardId);
        });
    });

    const packetCount = document.getElementById("packet-count");
    packetCount.innerText = `Всего пакетов: ${packets.length}`;
}


function addPacketCard(packet) {

    const card = document.createElement("div");
    card.classList.add("card");

    if (packet.info.length > 2) {
        card.classList.add("bg-success");
    }

    const packetId = document.createElement("p");
    packetId.hidden = true;
    packetId.classList.add("card-id");
    packetId.innerText = `${packet.id}`;
    card.appendChild(packetId);

    const cardBody = document.createElement("div");
    cardBody.classList.add("card-body");
    card.appendChild(cardBody);

    const idHeader = document.createElement("h5");
    idHeader.classList.add("card-title");
    if (packet.info.length > 2) {
        idHeader.innerText = `ID: ${packet.id}`;
    } else {
        idHeader.innerText = `ID: ${packet.id}`;
    }
    cardBody.appendChild(idHeader);

    const srcPara = document.createElement("p");
    srcPara.classList.add("card-text");
    srcPara.innerText = `${packet.src} -> ${packet.dst}`;
    cardBody.appendChild(srcPara);


    packetList.insertBefore(card, packetList.firstChild);
    requestAnimationFrame(() => {
        card.classList.add("appear");
    });

    if (sortByAppProtocol !== "ALL") {
        if (sortByAppProtocol !== packet.application_protocol) {
            card.hidden = true
        }
    }

}

function renderDetails(cardId) {
    const cardDetails = document.querySelector('.card-details .card-body');
    let packet = packets[cardId - 1]

    cardDetails.innerHTML = `
    <ul class="list-group list-group-flush">
    <li class="list-group-item">
    <p class="card-title">
    <h5 class="text-center">Packet ID: ${packet.id}</h5><br>
    IP отправителя: ${packet.src}<br>
    IP получателя: ${packet.dst}<br>
    Транспортный протокол: ${packet.transport_protocol}<br>
    Прикладной протокол: ${packet.application_protocol}<br>
    </p>
    </li>
    <li class="list-group-item">
    <p class="card-text"> Подробности: ${packet.info}</p>
    </li>
    </ul>
  `;
}
