import sys

# PyOtherSide vs. PySide2 Kompatibilitätslayer
try:
    import pyotherside
    USE_PYOTHERSIDE = True
except ImportError:
    from PySide2.QtCore import QObject, Signal as PySideSignal, Slot, Property, QUrl
    from PySide2.QtGui import QGuiApplication
    from PySide2.QtQuick import QQuickView
    from PySide2.QtQml import QQmlApplicationEngine
    from PySide2.QtWidgets import QApplication, QMessageBox
    USE_PYOTHERSIDE = False

# --- QObject-Ersatz für PyOtherSide ---
if USE_PYOTHERSIDE:
    class Signal:
        def __init__(self, *types):
            self._types = types
        
        def emit(self, *args):
            pyotherside.send('signal_emit', args)

    class QObject:
        def __init__(self):
            self._signals = {}

        def signal(self, name, *types):
            if name not in self._signals:
                self._signals[name] = Signal(*types)
            return self._signals[name]

    # Minimal-Implementierungen für Kompatibilität
    QGuiApplication = type('QGuiApplication', (), {
        'instance': lambda: None,
        'exec_': lambda: pyotherside.atexit_register(lambda: None)
    })
    
    QQuickView = type('QQuickView', (), {})
    QQmlApplicationEngine = type('QQmlApplicationEngine', (), {})
    QApplication = type('QApplication', (), {})
    QMessageBox = type('QMessageBox', (), {
        'information': staticmethod(lambda *args: None)
    })

else:
    # Original PySide2-Implementierungen
    Signal = PySideSignal
