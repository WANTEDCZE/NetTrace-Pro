"""NetTrace Pro application entry point."""
import sys
from PySide6.QtWidgets import QApplication
from gui import MainWindow

APP_NAME = "NetTrace Pro"

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    window = MainWindow()
    window.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
