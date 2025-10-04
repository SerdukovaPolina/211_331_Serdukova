#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QVector>
#include <QFile>
#include <QFileInfo>

#include <QTextStream>
#include <QDebug>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <QByteArray>
#include <QCryptographicHash>

struct Record {
    QString hash;
    QString cardNumberSource;
    QString cardNumberDestination;
    QString timestamp;
};

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QString defaultFilePath = "../../data.enc";
    QString defaultPin = "211331";

    void deriveKeyAndIVForFile(const QString &pin, QByteArray &key, QByteArray &iv);
    QByteArray decryptFile(const QByteArray &key, const QByteArray &iv, const QString& filename);

    void fillTable(const QVector<Record>& records);
    QVector<Record> parseFile(const QString& filename);
    QVector<Record> parseDecryptedData(const QByteArray& data);

    //void setUpTable(const QString& filename);









};
#endif // MAINWINDOW_H
