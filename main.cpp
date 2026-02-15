#include <QApplication>
#include <QIcon>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setDesktopFileName("ChatGPTKDE");
    const QString hardcodedIconPath = "/home/von/qt6 projects/ChatGPTKDE_beta/build/chatgptkde.png";
    app.setWindowIcon(QIcon(hardcodedIconPath));

    MainWindow w;
    w.setWindowIcon(QIcon(hardcodedIconPath));
    w.show();

    return app.exec();
}
