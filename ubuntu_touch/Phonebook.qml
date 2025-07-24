import QtQuick 2.7
import QtQuick.Controls 2.2 as QT
import Ubuntu.Components 1.3 as UT
import QtQuick.Layouts 1.2

Item {
    id: root
    property bool isUbuntuTouch: typeof UT.UbuntuColors !== 'undefined'
    
    // Farbdefinitionen
    readonly property color darkGreen: isUbuntuTouch ? UT.UbuntuColors.green : "#006400"
    readonly property color darkBlue: isUbuntuTouch ? UT.UbuntuColors.blue : "#00008B"
    readonly property color red: isUbuntuTouch ? UT.UbuntuColors.red : "#FF0000"
    readonly property color white: isUbuntuTouch ? UT.Theme.palette.normal.backgroundText : "#FFFFFF"
    readonly property color background: isUbuntuTouch ? UT.Theme.palette.normal.background : "black"
    readonly property color darkGrey: isUbuntuTouch ? UT.UbuntuColors.darkGrey : "#333333"

    // Größenanpassungen
    property int buttonHeight: isUbuntuTouch ? units.gu(7) : 60
    property int margin: isUbuntuTouch ? units.gu(2) : 10
    property int entryHeight: Math.max(root.height / 12, isUbuntuTouch ? units.gu(8) : 60)
    property int popupWidth: isUbuntuTouch ? units.gu(40) : 300
    property int popupHeight: isUbuntuTouch ? units.gu(30) : 200

    Loader {
        anchors.fill: parent
        sourceComponent: isUbuntuTouch ? utInterface : qtInterface
    }

    Component {
        id: utInterface
        UT.MainView {
            id: mainView
            width: units.gu(50)
            height: units.gu(80)
            anchorToKeyboard: true

            UT.Page {
                id: mainPage
                header: UT.PageHeader {
                    title: i18n.tr("PHONEBOOK")
                }

                Flickable {
                    anchors {
                        fill: parent
                        bottomMargin: buttonHeight + margin * 2
                    }
                    contentHeight: column.height
                    clip: true
                    boundsBehavior: Flickable.DragAndOvershootBounds

                    Column {
                        id: column
                        width: parent.width
                        spacing: margin/2

                        // Statusanzeige
                        UT.ListItem {
                            height: units.gu(5)
                            Label {
                                anchors.centerIn: parent
                                text: phonebook.connectionStatus
                                color: white
                            }
                            backgroundColor: darkGrey
                        }

                        // Telefonbuch-Einträge
                        Repeater {
                            model: phonebook.phonebookEntries
                            delegate: UT.ListItem {
                                height: entryHeight
                                backgroundColor: darkGreen
                                Label {
                                    anchors.centerIn: parent
                                    text: modelData.id + ": " + modelData.name
                                    color: white
                                    fontSize: "large"
                                    elide: Text.ElideRight
                                    maximumLineCount: 1
                                    width: parent.width - units.gu(4)
                                }
                                onClicked: phonebook.on_entry_click(index)
                                showDivider: false
                            }
                        }
                    }
                }

                // Button-Leiste
                RowLayout {
                    anchors {
                        bottom: parent.bottom
                        left: parent.left
                        right: parent.right
                        margins: margin
                    }
                    height: buttonHeight
                    spacing: margin

                    UT.Button {
                        Layout.fillWidth: true
                        text: i18n.tr("Update")
                        color: darkBlue
                        onClicked: phonebook.load_phonebook()
                    }

                    UT.Button {
                        Layout.fillWidth: true
                        text: i18n.tr("Setup")
                        color: darkBlue
                        onClicked: serverPopup.show()
                    }

                    UT.Button {
                        Layout.fillWidth: true
                        text: i18n.tr("Hang Up")
                        color: red
                        onClicked: phonebook.on_hangup_click()
                    }

                    UT.Button {
                        Layout.fillWidth: true
                        text: i18n.tr("Call")
                        color: darkGreen
                        onClicked: phonebook.on_call_click()
                    }
                }

                // Server Connection Popup für Ubuntu Touch
                UT.Dialog {
                    id: serverPopup
                    title: i18n.tr("Serververbindung")
                    Rectangle {
                        width: popupWidth
                        height: popupHeight
                        color: background

                        ColumnLayout {
                            anchors {
                                fill: parent
                                margins: margin
                            }
                            spacing: margin

                            RowLayout {
                                Layout.fillWidth: true
                                UT.Label {
                                    text: i18n.tr("Server-IP:")
                                    color: white
                                }
                                UT.TextField {
                                    id: serverIpField
                                    Layout.fillWidth: true
                                    placeholderText: "192.168.1.100"
                                    color: "black"
                                    backgroundColor: "white"
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                UT.Label {
                                    text: i18n.tr("Port:")
                                    color: white
                                }
                                UT.TextField {
                                    id: serverPortField
                                    Layout.fillWidth: true
                                    placeholderText: "8080"
                                    color: "black"
                                    backgroundColor: "white"
                                    inputMethodHints: Qt.ImhDigitsOnly
                                }
                            }

                            Item { Layout.fillHeight: true }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: margin

                                UT.Button {
                                    Layout.fillWidth: true
                                    text: i18n.tr("Abbrechen")
                                    color: red
                                    onClicked: serverPopup.hide()
                                }

                                UT.Button {
                                    Layout.fillWidth: true
                                    text: i18n.tr("Verbinden")
                                    color: darkGreen
                                    onClicked: {
                                        phonebook.on_connect_click(serverIpField.text, serverPortField.text)
                                        serverPopup.hide()
                                    }
                                }
                            }
                        }
                    }
                }

                // Call Status Popup für Ubuntu Touch
                UT.Dialog {
                    id: callStatusPopup
                    title: i18n.tr("Anrufstatus")
                    Rectangle {
                        width: popupWidth
                        height: units.gu(10)
                        color: darkBlue

                        UT.Label {
                            anchors.centerIn: parent
                            text: phonebook.callStatus
                            color: white
                            fontSize: "large"
                        }

                        UT.Button {
                            anchors {
                                top: parent.top
                                right: parent.right
                                margins: margin/2
                            }
                            width: units.gu(4)
                            height: units.gu(4)
                            color: red
                            iconName: "close"
                            onClicked: callStatusPopup.hide()
                        }
                    }
                }
            }
        }
    }

    Component {
        id: qtInterface
        QT.ApplicationWindow {
            id: window
            title: "PHONEBOOK"
            width: 600
            height: 1000
            visible: true
            color: background

            ColumnLayout {
                anchors.fill: parent
                spacing: margin

                // Statusanzeige
                Rectangle {
                    Layout.fillWidth: true
                    height: 40
                    color: darkGrey
                    QT.Label {
                        anchors.centerIn: parent
                        text: phonebook.connectionStatus
                        color: white
                    }
                }

                // Scrollbare Telefonbuchliste
                QT.ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true

                    QT.ListView {
                        id: listView
                        model: phonebook.phonebookEntries
                        spacing: 2
                        delegate: Rectangle {
                            width: listView.width
                            height: entryHeight
                            color: darkGreen
                            radius: 5

                            QT.Label {
                                anchors.centerIn: parent
                                text: modelData.id + ": " + modelData.name
                                color: white
                                font.pixelSize: 16
                                elide: Text.ElideRight
                                maximumLineCount: 1
                                width: parent.width - 20
                            }

                            QT.MouseArea {
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

                    QT.Button {
                        Layout.fillWidth: true
                        text: "Update"
                        background: Rectangle { color: darkBlue }
                        contentItem: QT.Label {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                        }
                        onClicked: phonebook.load_phonebook()
                    }

                    QT.Button {
                        Layout.fillWidth: true
                        text: "Setup"
                        background: Rectangle { color: darkBlue }
                        contentItem: QT.Label {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                        }
                        onClicked: serverPopup.open()
                    }

                    QT.Button {
                        Layout.fillWidth: true
                        text: "Hang Up"
                        background: Rectangle { color: red }
                        contentItem: QT.Label {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                        }
                        onClicked: phonebook.on_hangup_click()
                    }

                    QT.Button {
                        Layout.fillWidth: true
                        text: "Call"
                        background: Rectangle { color: darkGreen }
                        contentItem: QT.Label {
                            text: parent.text
                            color: white
                            horizontalAlignment: Text.AlignHCenter
                        }
                        onClicked: phonebook.on_call_click()
                    }
                }
            }

            // Server Connection Popup für Desktop
            QT.Popup {
                id: serverPopup
                width: popupWidth
                height: popupHeight
                x: (parent.width - width) / 2
                y: (parent.height - height) / 2
                modal: true
                closePolicy: QT.Popup.CloseOnEscape | QT.Popup.CloseOnPressOutside
                background: Rectangle {
                    color: background
                    border.color: darkGreen
                    border.width: 2
                    radius: 5
                }

                ColumnLayout {
                    anchors {
                        fill: parent
                        margins: margin
                    }
                    spacing: margin

                    QT.Label {
                        text: "Serververbindung"
                        font.bold: true
                        color: white
                        Layout.alignment: Qt.AlignHCenter
                    }

                    QT.TextField {
                        id: serverIpField
                        Layout.fillWidth: true
                        placeholderText: "Server-IP"
                        color: "black"
                        background: Rectangle { color: "white" }
                    }

                    QT.TextField {
                        id: serverPortField
                        Layout.fillWidth: true
                        placeholderText: "Port"
                        color: "black"
                        background: Rectangle { color: "white" }
                        inputMethodHints: Qt.ImhDigitsOnly
                    }

                    Item { Layout.fillHeight: true }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: margin

                        QT.Button {
                            Layout.fillWidth: true
                            text: "Abbrechen"
                            background: Rectangle { color: red }
                            contentItem: QT.Label {
                                text: parent.text
                                color: white
                                horizontalAlignment: Text.AlignHCenter
                            }
                            onClicked: serverPopup.close()
                        }

                        QT.Button {
                            Layout.fillWidth: true
                            text: "Verbinden"
                            background: Rectangle { color: darkGreen }
                            contentItem: QT.Label {
                                text: parent.text
                                color: white
                                horizontalAlignment: Text.AlignHCenter
                            }
                            onClicked: {
                                phonebook.on_connect_click(serverIpField.text, serverPortField.text)
                                serverPopup.close()
                            }
                        }
                    }
                }
            }

            // Call Status Popup für Desktop
            QT.Popup {
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

                QT.Label {
                    anchors.centerIn: parent
                    text: phonebook.callStatus
                    color: white
                    font.pixelSize: 18
                }

                QT.Button {
                    anchors {
                        top: parent.top
                        right: parent.right
                        margins: 5
                    }
                    width: 30
                    height: 30
                    background: Rectangle { color: red; radius: 15 }
                    contentItem: QT.Label {
                        text: "X"
                        color: white
                        anchors.centerIn: parent
                    }
                    onClicked: callStatusPopup.close()
                }
            }
        }
    }

    Connections {
        target: phonebook
        onCallStatusChanged: {
            if (isUbuntuTouch) {
                callStatusPopup.show()
            } else {
                callStatusPopup.open()
            }
        }
    }
}
