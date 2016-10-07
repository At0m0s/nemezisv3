#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <keystone/keystone.h>

ks_engine *ks;
ks_err err;
unsigned char *encode;
size_t sizes;
size_t counts;

ks_arch arch;
ks_mode mode;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    arch = KS_ARCH_X86;
    mode = KS_MODE_32;
}

MainWindow::~MainWindow()
{
    delete ui;
    ks_free(encode);
    ks_close(ks);
}

void MainWindow::on_archsCombo_currentIndexChanged(int index)
{
    switch(index) {
    case 0:
        arch = KS_ARCH_X86;
        mode = KS_MODE_32;
        break;
    case 1:
        arch = KS_ARCH_ARM;
        mode = KS_MODE_LITTLE_ENDIAN;
        break;
    case 2:
        arch = KS_ARCH_ARM64;
        mode = KS_MODE_LITTLE_ENDIAN;
        break;
    default:
        arch = KS_ARCH_X86;
        mode = KS_MODE_32;
        break;
    }
}

void MainWindow::on_convertBtn_clicked()
{
    QByteArray ba = ui->asmTextEdit->toPlainText().toLatin1();
    const char* _asm = (ba.data());

    QByteArray hex;

    err = ks_open(arch, mode, &ks);
    if(err != KS_ERR_OK) {
        printf("ERROR initializing KS\n");
    } else {
        //const char* _asm = "mov r1, #00";

        if(ks_asm(ks, _asm, 0, &encode, &sizes, &counts) != KS_ERR_OK) {
            printf("error parsing asm\n");
        } else {
            int i;
            printf("%s = ", _asm);
            for(i=0; i < sizes; i++) {
                printf("%02X ", encode[i]);
                hex.append(encode[i]);
            }
            printf("\nCompiled: %lu bytes, statements: %lu\n", sizes, counts);
        }
        // = QByteArray((const char*)encode);
        ui->hextTextEdit->setPlainText("0x" + QString(hex.toHex()));
    }
}
