#include <QApplication>
#include <QDir>
#include <QFile>
#include <QIcon>
#include <QPixmap>
#include <QWindow>
#include "mainwindow.h"

namespace {
QIcon loadAppIcon()
{
    const QStringList candidates = {
        QStringLiteral(":/assets/chatgpt-icon.png"),
        QDir(QStringLiteral(CHATGPTKDE_SOURCE_DIR)).filePath("assets/chatgpt-icon.png")
    };

    for (const QString &path : candidates) {
        if (!QFile::exists(path)) {
            continue;
        }

        const QPixmap pixmap(path);
        if (!pixmap.isNull()) {
            QIcon icon;
            icon.addPixmap(pixmap);
            return icon;
        }
    }

    return {};
}
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("chatgptkde");
    app.setDesktopFileName("ChatGPTKDE");
    const QIcon appIcon = loadAppIcon();
    app.setWindowIcon(appIcon);

    MainWindow w;
    w.setWindowIcon(appIcon);
    w.show();
    app.processEvents();
    if (QWindow *window = w.windowHandle()) {
        window->setIcon(appIcon);
    }

    return app.exec();
}
