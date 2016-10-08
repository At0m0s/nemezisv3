#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <keystone/keystone.h>
#include <inttypes.h>
#include <capstone/capstone.h>

ks_engine *ks;
ks_err err;
unsigned char *encode;
size_t sizes;
size_t counts;

csh cs;
cs_insn *insn;
size_t countcs;
cs_err c_err;

ks_arch k_arch;
ks_mode k_mode;

cs_arch c_arch;
cs_mode c_mode;

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    k_arch = KS_ARCH_X86;
    k_mode = KS_MODE_32;
    c_arch = CS_ARCH_X86;
    c_mode = CS_MODE_64;
}

MainWindow::~MainWindow()
{
    delete ui;
    ks_free(encode);
    ks_close(ks);
    cs_free(insn, countcs);
    cs_close(&cs);
}

void updateArchAndMode(int index, bool thumb, bool bend) {
    switch(index) {
    case 0:
        k_arch = KS_ARCH_X86;
        k_mode = KS_MODE_32;
        c_arch = CS_ARCH_X86;
        c_mode = CS_MODE_64;
        break;
    case 1:
        k_arch = KS_ARCH_ARM;
        if(thumb&&bend)
            k_mode = (ks_mode)(KS_MODE_BIG_ENDIAN | KS_MODE_THUMB);
        else if (thumb)
            k_mode = KS_MODE_THUMB;
        else if (bend)
            k_mode = KS_MODE_BIG_ENDIAN;
        else
            k_mode = KS_MODE_LITTLE_ENDIAN;
        break;
    case 2:
        k_arch = KS_ARCH_ARM64;
        if(thumb&&bend)
            k_mode = (ks_mode)(KS_MODE_BIG_ENDIAN | KS_MODE_THUMB);
        else if (thumb)
            k_mode = KS_MODE_THUMB;
        else if (bend)
            k_mode = KS_MODE_BIG_ENDIAN;
        else
            k_mode = KS_MODE_LITTLE_ENDIAN;
        break;
    case 3:
        k_arch = KS_ARCH_MIPS;
        k_mode = KS_MODE_MIPS32R6;
        break;
    default:
        k_arch = KS_ARCH_X86;
        k_mode = KS_MODE_32;
        break;
    }
}

void MainWindow::on_archsCombo_currentIndexChanged(int index)
{
    updateArchAndMode(index, ui->thumbBox->isChecked(), ui->bigEndianBox->isChecked());
}

void MainWindow::on_convertBtn_clicked()
{
    QByteArray ba = ui->asmTextEdit->toPlainText().toLatin1();
    const char* _asm = (ba.data());

    QByteArray hex;

    err = ks_open(k_arch, k_mode, &ks);
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

void MainWindow::on_thumbBox_toggled(bool checked)
{
    updateArchAndMode(ui->archsCombo->currentIndex(), checked, ui->bigEndianBox->isChecked());
}


void MainWindow::on_bigEndianBox_toggled(bool checked)
{
    updateArchAndMode(ui->archsCombo->currentIndex(), ui->thumbBox->isChecked(), checked);
}

void MainWindow::on_convertBackBtn_clicked()
{
    QList<QByteArray> q = ui->hextTextEdit->toPlainText().toLatin1().split('x');
    QByteArray ba = q[1];
    const uint8_t* _hex = //(const uint8_t*)"\x55\x48\x8b\x05\xb8\x13\x00\x00";
                          (const uint8_t*)(ba.toUInt(NULL, 16));

    QByteArray _asm;

    c_err = cs_open(c_arch,c_mode, &cs);
    if(c_err != CS_ERR_OK) {
        printf("Error in decompilation!");
    } else {
        countcs = cs_disasm(cs,
                            _hex,
                            sizeof(_hex)-1,
                            0x1000,
                            0,
                            &insn);
        if(countcs > 0) {
            size_t j;
            printf("opcodes: ");
            for (j=0; j<countcs+1; j++) {
                printf("%s\t\t%s", insn[j].mnemonic, insn[j].op_str);
                _asm.append(insn[j].mnemonic);
                _asm.append("\t\t");
                _asm.append(insn[j].op_str);
            }
        }
       ui->asmTextEdit->setPlainText(QString((const char*)_asm));
    }
}
