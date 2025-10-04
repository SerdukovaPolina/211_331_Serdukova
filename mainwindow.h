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

private slots:
    void on_openFile_clicked();

    void on_pushButton_clicked();

    void on_check_pin_clicked();

private:
    Ui::MainWindow *ui;
    QString defaultFilePath = "../../data.enc";
    QString currentFile = defaultFilePath;
    QString defaultPin = "211331";
    QString expectedHash = "14be53342d08c60b4d1dbe86caae8c5590735aa1602b3a095b12d2f8c9667601f0a127495dcce506e10c316e8d0a91d82ccce077891991e2740cb36a004a2081";

    void deriveKeyAndIVForFile(const QString &pin, QByteArray &key, QByteArray &iv);
    QByteArray decryptFile(const QByteArray &key, const QByteArray &iv, const QString& filename);

    void fillTable(const QVector<Record>& records);
    QVector<Record> parseDecryptedData(const QByteArray& data);

};
#endif // MAINWINDOW_H
