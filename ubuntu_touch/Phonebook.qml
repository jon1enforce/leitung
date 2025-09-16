import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

ApplicationWindow {
    id: mainWindow
    visible: true
    width: 600
    height: 1000
    minimumWidth: 400
    minimumHeight: 600
    title: qsTr("PHONEBOOK")
    color: "#000000"

    // Farbpalette
    readonly property color darkGreen: "#006400"
    readonly property color buttonBlue: "#1E90FF"
    readonly property color buttonRed: "#8B0000"
    readonly property color textWhite: "#FFFFFF"
    readonly property color backgroundDark: "#111111"
    readonly property color buttonDisabled: "#333333"

    // UI-Einstellungen
    property int buttonHeight: 60
    property int margin: 10
    property int entryHeight: 70
    property int popupWidth: 400

    // Statusvariablen
    property int selectedIndex: -1
    property string connectionStatus: "Disconnected"
    property string callStatus: ""
    property bool callInProgress: false
    property real callProgress: 0.0
    property string lastServerIp: "sichereleitung.duckdns.org"
    property string lastServerPort: "5060"

    // Phonebook data storage
    property ListModel phonebookModel: ListModel {}

    ColumnLayout {
        anchors.fill: parent
        spacing: margin

        // Statusbar
        Rectangle {
            Layout.fillWidth: true
            height: 40
            color: backgroundDark
            radius: 3
            
            RowLayout {
                anchors.fill: parent
                spacing: margin
                
                Text {
                    text: connectionStatus
                    color: textWhite
                    font { pixelSize: 16; bold: true }
                    Layout.leftMargin: margin
                }
                
                Text {
                    text: phonebook.clientName ? "User: " + phonebook.clientName : ""
                    color: textWhite
                    font { pixelSize: 16; italic: true }
                    Layout.alignment: Qt.AlignRight
                    Layout.rightMargin: margin
                }
            }
        }

        // Kontaktliste mit sichtbarem Scrollbalken
        ScrollView {
            id: phonebookScrollView
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            ScrollBar.vertical: ScrollBar {
                id: verticalScrollBar
                active: true
                policy: ScrollBar.AsNeeded
                width: 12
                padding: 1
                
                background: Rectangle {
                    color: backgroundDark
                    radius: 6
                }
                
                contentItem: Rectangle {
                    color: darkGreen
                    radius: 5
                    opacity: verticalScrollBar.active ? 0.75 : 0
                    Behavior on opacity { NumberAnimation { duration: 200 } }
                }
            }

            ListView {
                id: listView
                width: parent.width
                height: Math.min(contentHeight, phonebookScrollView.availableHeight)
                model: phonebookModel
                spacing: 4
                currentIndex: selectedIndex
                boundsBehavior: Flickable.StopAtBounds
                cacheBuffer: entryHeight * 20
                
                delegate: Rectangle {
                    width: listView.width
                    height: entryHeight
                    color: darkGreen
                    radius: 5
                    border.color: selectedIndex === index ? textWhite : "transparent"
                    border.width: 2

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 10

                        Text {
                            text: model.id + ":"
                            color: textWhite
                            font { pixelSize: 16; bold: true }
                            Layout.preferredWidth: 30
                        }

                        Text {
                            text: model.name
                            color: textWhite
                            font.pixelSize: 16
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            selectedIndex = index
                            phonebook.on_entry_click(index)
                        }
                    }
                }

                Label {
                    visible: listView.count === 0
                    width: listView.width
                    height: entryHeight * 2
                    text: "No entries found"
                    color: textWhite
                    font { pixelSize: 18; italic: true }
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }

        // Button-Leiste (4 gleich große Buttons)
        RowLayout {
            Layout.fillWidth: true
            height: buttonHeight
            spacing: margin

            // Update Button
            Button {
                Layout.fillWidth: true
                Layout.preferredHeight: buttonHeight
                text: "Update"
                background: Rectangle {
                    color: buttonBlue
                    radius: 5
                }
                contentItem: Text {
                    text: parent.text
                    color: textWhite
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font { pixelSize: 16; bold: true }
                }
                onClicked: {
                    phonebook.on_update_click()
                }
            }

            // Setup Button
            Button {
                Layout.fillWidth: true
                Layout.preferredHeight: buttonHeight
                text: "Setup"
                background: Rectangle {
                    color: buttonBlue
                    radius: 5
                }
                contentItem: Text {
                    text: parent.text
                    color: textWhite
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font { pixelSize: 16; bold: true }
                }
                onClicked: {
                    serverSetupPopup.open()
                }
            }

            // Call Button
            Button {
                Layout.fillWidth: true
                Layout.preferredHeight: buttonHeight
                text: "Call"
                enabled: selectedIndex !== -1
                background: Rectangle {
                    color: enabled ? darkGreen : buttonDisabled
                    radius: 5
                }
                contentItem: Text {
                    text: parent.text
                    color: textWhite
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font { pixelSize: 16; bold: true }
                }
                onClicked: {
                    callInProgress = true
                    callProgress = 0.0
                    phonebook.on_call_click()
                }
            }

            // Hang Up Button
            Button {
                Layout.fillWidth: true
                Layout.preferredHeight: buttonHeight
                text: "Hang Up"
                background: Rectangle {
                    color: buttonRed
                    radius: 5
                }
                contentItem: Text {
                    text: parent.text
                    color: textWhite
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font { pixelSize: 16; bold: true }
                }
                onClicked: {
                    callInProgress = false
                    phonebook.on_hangup_click()
                }
            }
        }
    }

    // Server Setup Popup
    Popup {
        id: serverSetupPopup
        width: popupWidth
        height: 250
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

        background: Rectangle {
            color: backgroundDark
            radius: 5
            border.color: buttonBlue
            border.width: 2
        }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: margin
            spacing: margin

            Text {
                text: "SERVER CONNECTION"
                color: textWhite
                font { pixelSize: 18; bold: true }
                Layout.alignment: Qt.AlignHCenter
            }

            TextField {
                id: ipField
                Layout.fillWidth: true
                placeholderText: "Server IP"
                text: lastServerIp
                color: "black"
                background: Rectangle {
                    color: "white"
                    radius: 3
                }
                font.pixelSize: 16
                validator: RegExpValidator {
                    regExp: /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
                }
            }

            TextField {
                id: portField
                Layout.fillWidth: true
                placeholderText: "Port"
                text: lastServerPort
                color: "black"
                background: Rectangle {
                    color: "white"
                    radius: 3
                }
                font.pixelSize: 16
                inputMethodHints: Qt.ImhDigitsOnly
                validator: IntValidator {
                    bottom: 1
                    top: 65535
                }
            }

            Item { Layout.fillHeight: true }

            RowLayout {
                Layout.fillWidth: true
                spacing: margin

                Button {
                    Layout.fillWidth: true
                    text: "Cancel"
                    background: Rectangle {
                        color: buttonRed
                        radius: 5
                    }
                    contentItem: Text {
                        text: parent.text
                        color: textWhite
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        font { pixelSize: 16; bold: true }
                    }
                    onClicked: {
                        serverSetupPopup.close()
                    }
                }

                Button {
                    Layout.fillWidth: true
                    text: "Connect"
                    background: Rectangle {
                        color: darkGreen
                        radius: 5
                    }
                    contentItem: Text {
                        text: parent.text
                        color: textWhite
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        font { pixelSize: 16; bold: true }
                    }
                    onClicked: {
                        lastServerIp = ipField.text
                        lastServerPort = portField.text
                        phonebook.on_connect_click(ipField.text, portField.text)
                        serverSetupPopup.close()
                    }
                }
            }
        }
    }

    // Name Input Popup
    Popup {
        id: nameInputPopup
        width: popupWidth
        height: 200
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        closePolicy: Popup.NoAutoClose
        
        background: Rectangle {
            color: backgroundDark
            radius: 5
            border.color: buttonBlue
            border.width: 2
        }
        
        ColumnLayout {
            anchors.fill: parent
            anchors.margins: margin
            spacing: margin
            
            Text {
                text: "CLIENT NAME REQUIRED"
                color: textWhite
                font { pixelSize: 18; bold: true }
                Layout.alignment: Qt.AlignHCenter
            }
            
            TextField {
                id: nameInputField
                Layout.fillWidth: true
                placeholderText: "Enter your name"
                color: "black"
                background: Rectangle {
                    color: "white"
                    radius: 3
                }
                font.pixelSize: 16
            }
            
            Item { Layout.fillHeight: true }
            
            RowLayout {
                Layout.fillWidth: true
                spacing: margin
                
                Button {
                    Layout.fillWidth: true
                    text: "Cancel"
                    background: Rectangle {
                        color: buttonRed
                        radius: 5
                    }
                    contentItem: Text {
                        text: parent.text
                        color: textWhite
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        font { pixelSize: 16; bold: true }
                    }
                    onClicked: {
                        nameInputPopup.close()
                        connectionStatus = "Connection canceled - No name provided"
                    }
                }
                
                Button {
                    Layout.fillWidth: true
                    text: "Save"
                    background: Rectangle {
                        color: darkGreen
                        radius: 5
                    }
                    contentItem: Text {
                        text: parent.text
                        color: textWhite
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        font { pixelSize: 16; bold: true }
                    }
                    onClicked: {
                        if (nameInputField.text.trim() !== "") {
                            phonebook.save_client_name(nameInputField.text.trim())
                            nameInputPopup.close()
                            phonebook.on_connect_click(lastServerIp, lastServerPort)
                        }
                    }
                }
            }
        }
    }

    // Call Status Popup
    Popup {
        id: callStatusPopup
        width: popupWidth
        height: 150
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        closePolicy: Popup.NoAutoClose
        visible: callInProgress

        background: Rectangle {
            color: backgroundDark
            radius: 10
            border.color: darkGreen
            border.width: 2
        }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 10
            spacing: 10

            Text {
                text: callStatus || "Call in progress..."
                color: textWhite
                font.pixelSize: 18
                font.bold: true
                Layout.alignment: Qt.AlignHCenter
            }

            ProgressBar {
                Layout.fillWidth: true
                value: callProgress
                from: 0
                to: 1
                indeterminate: callProgress === 0
            }

            Button {
                Layout.alignment: Qt.AlignHCenter
                text: "Cancel"
                background: Rectangle {
                    color: buttonRed
                    radius: 5
                }
                contentItem: Text {
                    text: parent.text
                    color: textWhite
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font { pixelSize: 16; bold: true }
                }
                onClicked: {
                    callInProgress = false
                    callStatusPopup.close()
                    phonebook.on_hangup_click()
                }
            }
        }
    }

    Component.onCompleted: {
        console.log("QML Application started");
    }

    Connections {
        target: phonebook
        
        function onConnectionStatusChanged(status) {
            connectionStatus = status;
        }
        
        function onCallStatusChanged(status) {
            callStatus = status;
        }
        
        function onPhonebookUpdated(data) {
            console.log("Phonebook update received");
            
            phonebookModel.clear();
            
            if (Array.isArray(data)) {
                for (var i = 0; i < data.length; i++) {
                    var client = data[i];
                    if (client && typeof client === 'object') {
                        phonebookModel.append({
                            id: client.id || "N/A",
                            name: client.name || "Unknown",
                            ip: client.ip || "",
                            port: client.port || "",
                            public_key: client.public_key || ""
                        });
                    }
                }
                
                connectionStatus = "Phonebook: " + data.length + " entries";
                
            } else {
                console.log("ERROR: Received data is not an array");
                connectionStatus = "Error: Invalid data format";
            }
        }
        
        function onServerSettingsChanged(ip, port) {
            lastServerIp = ip;
            lastServerPort = port;
        }
        
        function onClientNameRequested() {
            nameInputPopup.open();
        }
        
        function onClientNameChanged(name) {
            console.log("Client name changed to: " + name);
        }
    }
}
