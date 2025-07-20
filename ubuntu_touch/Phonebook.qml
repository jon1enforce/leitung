import QtQuick 2.9
import QtQuick.Controls 2.2
import QtQuick.Layouts 1.3

ApplicationWindow {
    id: root
    title: "PHONEBOOK, mein Telefonbuch"
    width: 600
    height: 1000
    visible: true
    color: "black"

    // Color definitions
    readonly property color darkGreen: "#006400"
    readonly property color darkBlue: "#00008B"
    readonly property color white: "#FFFFFF"
    
    property int buttonHeight: 60
    property int margin: 10

    TabBar {
        id: tabBar
        width: parent.width
        TabButton {
            text: "Telefonbuch"
            contentItem: Text {
                text: parent.text
                color: white
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
            }
            background: Rectangle { color: darkGreen }
        }
    }

    StackLayout {
        width: parent.width
        height: parent.height - tabBar.height
        currentIndex: tabBar.currentIndex

        Item {
            // Telefonbuch-Tab
            ColumnLayout {
                anchors.fill: parent
                spacing: margin

                // Statusanzeige
                Rectangle {
                    Layout.fillWidth: true
                    height: 40
                    color: "darkgrey"
                    Text {
                        anchors.centerIn: parent
                        text: phonebook.connectionStatus
                        color: white
                        font.pixelSize: 16
                    }
                }

                // Telefonbuch-Einträge
                ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true

                    ListView {
                        id: listView
                        model: phonebook.phonebookEntries
                        delegate: Rectangle {
                            width: listView.width
                            height: 60
                            color: darkGreen
                            radius: 5

                            Text {
                                anchors.centerIn: parent
                                text: modelData.id + ": " + modelData.name
                                color: white
                                font.pixelSize: 16
                            }

                            MouseArea {
                                anchors.fill: parent
                                onClicked: phonebook.on_entry_click(index)
                            }
                        }
                    }
                }

                // Steuerbuttons - now with equal width and proper colors
                RowLayout {
                    Layout.fillWidth: true
                    height: buttonHeight
                    spacing: margin

                    Button {
                        Layout.fillWidth: true
                        text: "Update"
                        onClicked: phonebook.load_phonebook()
                        background: Rectangle { color: darkGreen }
                        contentItem: Text {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }

                    Button {
                        Layout.fillWidth: true
                        text: "Setup"
                        onClicked: settingsPopup.open()
                        background: Rectangle { color: darkGreen }
                        contentItem: Text {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }

                    Button {
                        Layout.fillWidth: true
                        text: "Hang Up"
                        onClicked: phonebook.on_hangup_click()
                        background: Rectangle { color: darkBlue }
                        contentItem: Text {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }

                    Button {
                        Layout.fillWidth: true
                        text: "Call"
                        onClicked: phonebook.on_call_click()
                        background: Rectangle { color: darkBlue }
                        contentItem: Text {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
            }
        }
    }

    // Server Connection Popup (now clean without settings buttons)
    Popup {
        id: settingsPopup
        width: 300
        height: 200  // Reduced height
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: margin
            spacing: margin

            Label {
                text: "Serververbindung"
                font.bold: true
                color: white
                Layout.alignment: Qt.AlignHCenter
            }

            TextField {
                id: serverIpField
                Layout.fillWidth: true
                placeholderText: "Server-IP"
                color: "black"
                background: Rectangle { color: white }
            }

            TextField {
                id: serverPortField
                Layout.fillWidth: true
                placeholderText: "Port"
                color: "black"
                background: Rectangle { color: white }
            }

            Button {
                Layout.fillWidth: true
                text: "Verbinden"
                onClicked: {
                    phonebook.on_connect_click(serverIpField.text, serverPortField.text)
                    settingsPopup.close()
                }
                background: Rectangle { color: darkGreen }
                contentItem: Text {
                    text: parent.text
                    color: white
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
    }

    // Settings Popup (new separate popup for keyboard/language)
    Popup {
        id: configPopup
        width: 250
        height: 150
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        
        ColumnLayout {
            anchors.fill: parent
            anchors.margins: margin
            spacing: margin
            
            Label {
                text: "Einstellungen"
                font.bold: true
                color: white
                Layout.alignment: Qt.AlignHCenter
            }
            
            Button {
                Layout.fillWidth: true
                text: "Tastatur"
                onClicked: {
                    phonebook.open_keyboard_settings()
                    configPopup.close()
                }
                background: Rectangle { color: darkGreen }
                contentItem: Text {
                    text: parent.text
                    color: white
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
            
            Button {
                Layout.fillWidth: true
                text: "Sprache"
                onClicked: {
                    phonebook.open_language_settings()
                    configPopup.close()
                }
                background: Rectangle { color: darkGreen }
                contentItem: Text {
                    text: parent.text
                    color: white
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
    }

    // Call Status Popup
    Popup {
        id: callStatusPopup
        width: 300
        height: 100
        x: (parent.width - width) / 2
        y: (parent.height - height) / 2
        modal: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        background: Rectangle { color: darkBlue }

        Label {
            anchors.centerIn: parent
            text: phonebook.callStatus
            color: white
            font.pixelSize: 18
        }
    }

	Popup {
		id: nameInputPopup
		width: 300
		height: 200
		modal: true
		
		ColumnLayout {
			anchors.fill: parent
			spacing: 10
			
			Label {
				text: "Bitte geben Sie Ihren Namen ein:"
				color: "white"
			}
			
			TextField {
				id: nameInputField
				Layout.fillWidth: true
				color: "black"
				background: Rectangle { color: "white" }
			}
			
			Button {
				Layout.fillWidth: true
				text: "Bestätigen"
				onClicked: {
					phonebook.set_client_name(nameInputField.text)
					nameInputPopup.close()
				}
				background: Rectangle { color: "#006400" }
				contentItem: Text {
					text: parent.text
					color: "white"
					horizontalAlignment: Text.AlignHCenter
				}
			}
		}
	}


    Connections {
        target: phonebook
        onCallStatusChanged: callStatusPopup.open()
        onRequestClientName: nameInputPopup.open()
    }
}
