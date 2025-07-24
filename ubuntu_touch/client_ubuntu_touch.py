import QtQuick 2.7
import QtQuick.Controls 2.7
import QtQuick.Layouts 1.3
#fallback
#import QtQuick 2.5
#import QtQuick.Controls 2.5
#import QtQuick.Layouts 1.2


ApplicationWindow {
    id: mainWindow
    visible: true
    width: 600
    height: 1000
    title: "PHONEBOOK"
    color: "black"

    // Farbdefinitionen
    readonly property color darkGreen: "#006400"
    readonly property color darkBlue: "#00008B"
    readonly property color red: "#FF0000"
    readonly property color white: "#FFFFFF"
    readonly property color darkGrey: "#333333"

    // Größenanpassungen
    property int buttonHeight: 60
    property int margin: 10
    property int entryHeight: Math.max(height / 12, 60)
    property int popupWidth: 300
    property int popupHeight: 200

    ColumnLayout {
        anchors.fill: parent
        spacing: margin

        // Statusanzeige
        Rectangle {
            Layout.fillWidth: true
            height: 40
            color: darkGrey
            Text {
                anchors.centerIn: parent
                text: phonebook.connectionStatus
                color: white
                font.pixelSize: 16
            }
        }

        // Telefonbuchliste
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            ListView {
                id: listView
                model: phonebook.phonebookEntries
                spacing: 2
                delegate: Rectangle {
                    width: listView.width
                    height: entryHeight
                    color: darkGreen
                    radius: 5

                    Text {
                        anchors.centerIn: parent
                        text: modelData.id + ": " + modelData.name
                        color: white
                        font.pixelSize: 16
                        elide: Text.ElideRight
                        maximumLineCount: 1
                        width: parent.width - 20
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: phonebook.on_entry_click(index)
                    }
                }
            }
        }

        // Button-Leiste
        RowLayout {
            Layout.fillWidth: true
            height: buttonHeight
            spacing: margin

            Button {
                Layout.fillWidth: true
                text: "Update"
                background: Rectangle { color: darkBlue }
                contentItem: Text {
                    text: parent.text
                    color: white
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                onClicked: phonebook.load_phonebook()
            }

            Button {
                Layout.fillWidth: true
                text: "Setup"
                background: Rectangle { color: darkBlue }
                contentItem: Text {
                    text: parent.text
                    color: white
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                onClicked: serverPopup.open()
            }

            Button {
                Layout.fillWidth: true
                text: "Hang Up"
                background: Rectangle { color: red }
                contentItem: Text {
                    text: parent.text
                    color: white
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                onClicked: phonebook.on_hangup_click()
            }

            Button {
                Layout.fillWidth: true
                text: "Call"
                background: Rectangle { color: darkGreen }
                contentItem: Text {
                    text: parent.text
                    color: white
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                onClicked: phonebook.on_call_click()
            }
        }
    }

    // Server Connection Popup
    Popup {
        id: serverPopup
        width: popupWidth
        height: popupHeight
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        background: Rectangle {
            color: "black"
            border.color: darkGreen
            border.width: 2
            radius: 5
        }

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: margin
            spacing: margin

            Text {
                text: "Serververbindung"
                font.bold: true
                color: white
                Layout.alignment: Qt.AlignHCenter
                font.pixelSize: 16
            }

            TextField {
                id: serverIpField
                Layout.fillWidth: true
                placeholderText: "Server-IP"
                color: "black"
                background: Rectangle { color: "white" }
                font.pixelSize: 14
            }

            TextField {
                id: serverPortField
                Layout.fillWidth: true
                placeholderText: "Port"
                color: "black"
                background: Rectangle { color: "white" }
                inputMethodHints: Qt.ImhDigitsOnly
                font.pixelSize: 14
            }

            Item { Layout.fillHeight: true }

            RowLayout {
                Layout.fillWidth: true
                spacing: margin

                Button {
                    Layout.fillWidth: true
                    text: "Abbrechen"
                    background: Rectangle { color: red }
                    contentItem: Text {
                        text: parent.text
                        color: white
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    onClicked: serverPopup.close()
                }

                Button {
                    Layout.fillWidth: true
                    text: "Verbinden"
                    background: Rectangle { color: darkGreen }
                    contentItem: Text {
                        text: parent.text
                        color: white
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    onClicked: {
                        phonebook.on_connect_click(serverIpField.text, serverPortField.text)
                        serverPopup.close()
                    }
                }
            }
        }
    }

    // Call Status Popup
    Popup {
        id: callStatusPopup
        width: popupWidth
        height: 100
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        background: Rectangle {
            color: darkBlue
            radius: 5
        }

        Text {
            anchors.centerIn: parent
            text: phonebook.callStatus
            color: white
            font.pixelSize: 18
        }

        Button {
            anchors {
                top: parent.top
                right: parent.right
                margins: 5
            }
            width: 30
            height: 30
            background: Rectangle { color: red; radius: 15 }
            contentItem: Text {
                text: "X"
                color: white
                anchors.centerIn: parent
            }
            onClicked: callStatusPopup.close()
        }
    }

    Connections {
        target: phonebook
        onCallStatusChanged: callStatusPopup.open()
    }
}
