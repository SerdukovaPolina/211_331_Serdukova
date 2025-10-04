#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    /*QByteArray key, iv;
    deriveKeyAndIVForFile(defaultPin, key, iv);
    QByteArray decryptedData = decryptFile(key, iv, defaultFilePath);

    QVector<Record> records = parseDecryptedData(decryptedData);

    QFile file(defaultFilePath);
    QFileInfo fileInfo(file);
    ui->file_path->setText(fileInfo.absoluteFilePath());

    key.fill(0);
    iv.fill(0);

    fillTable(records);

    ui->stackedWidget->setCurrentWidget(ui->Data_page);*/

    ui->wrong_pin->setVisible(false);
    ui->stackedWidget->setCurrentWidget(ui->Pin_page);

    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

}

MainWindow::~MainWindow()
{
    delete ui;
}

//Извленчение ключа и вектора для AES-256-cbc расшифрования
void MainWindow::deriveKeyAndIVForFile(const QString &pin, QByteArray &key, QByteArray &iv) {
    QString s = "serdukova";
    QByteArray salt = s.toUtf8();
    QByteArray pinCode = pin.toUtf8();
    QByteArray hash = QCryptographicHash::hash(pinCode + salt, QCryptographicHash::Sha512);

    key = hash.left(32);
    iv = hash.mid(16, 16);

    qDebug() << key.toHex();
    qDebug() << iv.toHex();
}


//Расшифрование файла AES-256-cbc
QByteArray MainWindow::decryptFile(const QByteArray &key, const QByteArray &iv, const QString& filename)
{
    QFile inputFile(filename);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qWarning() << "Ошибка открытия файла!";
        return {};
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qWarning() << "Ошибка создания контекста OpenSSL!";
        return {};
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       reinterpret_cast<const unsigned char*>(key.data()),
                       reinterpret_cast<const unsigned char*>(iv.data()));

    QByteArray decryptedData;
    QByteArray buffer(4096, 0);
    QByteArray decryptedBuffer(4096 + EVP_CIPHER_block_size(EVP_aes_256_cbc()), 0);

    int outLen = 0;
    while (!inputFile.atEnd()) {
        int bytesRead = inputFile.read(buffer.data(), buffer.size());
        EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(decryptedBuffer.data()), &outLen,
                          reinterpret_cast<const unsigned char*>(buffer.constData()), bytesRead);
        decryptedData.append(decryptedBuffer.constData(), outLen);
    }

    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(decryptedBuffer.data()), &outLen);
    decryptedData.append(decryptedBuffer.constData(), outLen);

    EVP_CIPHER_CTX_free(ctx);

    return decryptedData;
}


//Заполнение таблицы на сонвое переданного массива записей
void MainWindow::fillTable(const QVector<Record>& records)
{
    this->setWindowTitle("Данные");

    ui->tableWidget->clear();
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setColumnCount(4); // обязательно перед установкой заголовков

    // Устанавливаем заголовки столбцов
    ui->tableWidget->setHorizontalHeaderLabels(QStringList()
                                               << "Хэш-код"
                                               << "Номер счёта списания"
                                               << "Номер счёта поступления"
                                               << "Дата и время (ISO 8601)");

    if (records.size() == 0) {
        ui->no_data->setVisible(true);
    } else {
        ui->no_data->setVisible(false);
    }

    for (int i = 0; i < records.size(); ++i) {
        ui->tableWidget->insertRow(i);

        ui->tableWidget->setItem(i, 0, new QTableWidgetItem(records[i].hash));
        ui->tableWidget->setItem(i, 1, new QTableWidgetItem(records[i].cardNumberSource));
        ui->tableWidget->setItem(i, 2, new QTableWidgetItem(records[i].cardNumberDestination));
        ui->tableWidget->setItem(i, 3, new QTableWidgetItem(records[i].timestamp));
    }

    ui->tableWidget->resizeColumnsToContents();
}

//Парсинг QByteArray расшифрованных данных
QVector<Record> MainWindow::parseDecryptedData(const QByteArray& data)
{
    QVector<Record> records;
    QList<QByteArray> buffer;

    // Разбиваем по строкам (\n или \r\n)
    QList<QByteArray> lines = data.split('\n');

    for (QByteArray& line : lines) {
        line = line.trimmed(); // удаляет \r, пробелы и т.п.
        if (line.isEmpty())
            continue;

        buffer.append(line);

        if (buffer.size() == 4) {
            Record rec;
            rec.hash = QString::fromUtf8(buffer[0]);
            rec.cardNumberSource = QString::fromUtf8(buffer[1]);
            rec.cardNumberDestination = QString::fromUtf8(buffer[2]);
            rec.timestamp = QString::fromUtf8(buffer[3]);
            records.append(rec);
            buffer.clear();
        }
    }

    if (!buffer.isEmpty()) {
        qWarning() << "Неполная запись в конце файла!";
    }

    return records;
}

//Переход на форму ввода пути файла для открытия
void MainWindow::on_openFile_clicked()
{
    ui->stackedWidget->setCurrentWidget(ui->Open_page);
    this->setWindowTitle("Открыть файл");
}

//Открытие нового файла + парсинг
void MainWindow::on_pushButton_clicked()
{
    QString filename = ui->filename_entered->text();
    QFile file(filename);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        ui->open_failed->setStyleSheet("color: red;");
        ui->open_failed->setText("Не уделось открыть указанный файл!");
        ui->filename_entered->clear();
    } else {
        currentFile = filename;
        ui->filename_entered->clear();
        QByteArray key, iv;
        deriveKeyAndIVForFile(defaultPin, key, iv);
        QByteArray decryptedData = decryptFile(key, iv, filename);

        QVector<Record> records = parseDecryptedData(decryptedData);
        qDebug() << records.size();
        QFile file(filename);
        QFileInfo fileInfo(file);
        ui->file_path->setText(fileInfo.absoluteFilePath());

        key.fill(0);
        iv.fill(0);

        fillTable(records);

        ui->stackedWidget->setCurrentWidget(ui->Data_page);
    }

}


void MainWindow::on_check_pin_clicked()
{

    QByteArray pin = ui->pin->text().toUtf8();

    QByteArray hash = QCryptographicHash::hash(pin, QCryptographicHash::Sha512);

    qDebug() << hash.toHex();

    if (hash == QByteArray::fromHex(expectedHash.toUtf8())) {
        qDebug() << "Correct pin";
        ui->wrong_pin->setVisible(false);
        ui->stackedWidget->setCurrentWidget(ui->Data_page);
    } else {
        qDebug() << "Incorrect pin";
        ui->wrong_pin->setVisible(true);
    }

}

