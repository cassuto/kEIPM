/********************************************************************************
** Form generated from reading UI file 'widget.ui'
**
** Created by: Qt User Interface Compiler version 5.9.9
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WIDGET_H
#define UI_WIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Widget
{
public:
    QVBoxLayout *verticalLayout_9;
    QTabWidget *tabWidget;
    QWidget *CASign;
    QVBoxLayout *verticalLayout;
    QGroupBox *groupBox_ELF;
    QVBoxLayout *verticalLayout_4;
    QWidget *widget;
    QHBoxLayout *horizontalLayout;
    QLabel *lab_CASign_CA;
    QLineEdit *lineEd_CASign_CA;
    QPushButton *Btn_CASign_CA;
    QWidget *widget_2;
    QHBoxLayout *horizontalLayout_8;
    QLabel *lab_CASign_elf;
    QTreeView *treeView_CASign_elf;
    QFrame *frame_6;
    QHBoxLayout *horizontalLayout_6;
    QSpacerItem *horizontalSpacer;
    QPushButton *Btn_Inport;
    QPushButton *Btn_Cancel;
    QWidget *RsaSign;
    QVBoxLayout *verticalLayout_6;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout_5;
    QWidget *widget_3;
    QHBoxLayout *horizontalLayout_9;
    QLabel *lab_RsaSign_rsa;
    QLineEdit *lineEd_RsaSign_rsa;
    QPushButton *Btn_RsaSign_rsa;
    QWidget *widget_4;
    QHBoxLayout *horizontalLayout_10;
    QLabel *lab_RsaSign_elf;
    QTreeView *treeView_RsaSign_elf;
    QFrame *frame_7;
    QHBoxLayout *horizontalLayout_11;
    QSpacerItem *horizontalSpacer_4;
    QPushButton *Btn_RsaSign_Inport;
    QPushButton *Btn_Rsa_Sign_Cancel;
    QWidget *Create_Rsa;
    QVBoxLayout *verticalLayout_8;
    QGroupBox *groupBox_4;
    QHBoxLayout *horizontalLayout_12;
    QLabel *label;
    QPushButton *Btn_GetRsa_Create_privateKey;
    QGroupBox *groupBox_3;
    QGridLayout *gridLayout;
    QLineEdit *lineEd_GetRsa_inport_public_privateKey;
    QLabel *lab_GetRsa_inport_public_privateKey;
    QPushButton *Btn_GetRsa_publicKey;
    QPushButton *Btn_GetRsa_Create_publicKey;
    QGroupBox *groupBox_2;
    QVBoxLayout *verticalLayout_7;
    QWidget *widget_8;
    QHBoxLayout *horizontalLayout_18;
    QSpacerItem *horizontalSpacer_7;
    QSpacerItem *horizontalSpacer_8;
    QSpacerItem *horizontalSpacer_9;
    QPushButton *Btn_GetRsa_Create;
    QSpacerItem *horizontalSpacer_5;
    QPushButton *Btn_GetRsa_Cancel;
    QWidget *Create_RootCA;
    QVBoxLayout *verticalLayout_2;
    QGroupBox *gBox_RootCA_Inf;
    QFormLayout *formLayout_3;
    QLineEdit *lineEd_RootCountry;
    QLabel *lab_RootState;
    QLineEdit *lineEd_RootState;
    QLabel *lab_RootLocality;
    QLineEdit *lineEd_RootLocality;
    QLabel *lab_RootOrganiz;
    QLineEdit *lineEd_RootOrganization;
    QLabel *lab_RootCommon;
    QLineEdit *lineEd_RootCommon;
    QLabel *lab_RootCountry;
    QLabel *lab_RootLimit;
    QSpinBox *spinBox_RootLimit;
    QFrame *frame_2;
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *Btn_output_RootCA;
    QPushButton *Btn_outClose_RootCA;
    QWidget *Create_UserCA;
    QVBoxLayout *verticalLayout_3;
    QFrame *frame_3;
    QHBoxLayout *horizontalLayout_3;
    QLabel *lab_User_inputRootCA;
    QLineEdit *lineEd_User_InputPath_RootCA;
    QPushButton *Btn_User_Visit_RootCA;
    QGroupBox *gBox_UserCA_Inf;
    QFormLayout *formLayout_2;
    QLineEdit *lineEd_UserCountry;
    QLabel *lab_UserState;
    QLineEdit *lineEd_UserState;
    QLabel *lab_UserLocality;
    QLineEdit *lineEd_UserLocality;
    QLabel *lab_UserOrganiz;
    QLineEdit *lineEd_UserOrganization;
    QLabel *lab_UserCommon;
    QLineEdit *lineEd_UserCommon;
    QLabel *lab_UserCountry;
    QLabel *lab_UserLimit;
    QSpinBox *spinBox_UserLimit;
    QFrame *frame_5;
    QHBoxLayout *horizontalLayout_5;
    QSpacerItem *horizontalSpacer_3;
    QPushButton *pushButton_2;
    QPushButton *pushButton;
    QWidget *widget_5;
    QHBoxLayout *horizontalLayout_14;
    QSpacerItem *horizontalSpacer_6;
    QCheckBox *Manage_model;

    void setupUi(QWidget *Widget)
    {
        if (Widget->objectName().isEmpty())
            Widget->setObjectName(QStringLiteral("Widget"));
        Widget->resize(527, 454);
        Widget->setMaximumSize(QSize(16777215, 16777215));
        verticalLayout_9 = new QVBoxLayout(Widget);
        verticalLayout_9->setObjectName(QStringLiteral("verticalLayout_9"));
        tabWidget = new QTabWidget(Widget);
        tabWidget->setObjectName(QStringLiteral("tabWidget"));
        tabWidget->setTabPosition(QTabWidget::North);
        tabWidget->setTabShape(QTabWidget::Rounded);
        tabWidget->setElideMode(Qt::ElideNone);
        tabWidget->setMovable(true);
        CASign = new QWidget();
        CASign->setObjectName(QStringLiteral("CASign"));
        verticalLayout = new QVBoxLayout(CASign);
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        groupBox_ELF = new QGroupBox(CASign);
        groupBox_ELF->setObjectName(QStringLiteral("groupBox_ELF"));
        groupBox_ELF->setMaximumSize(QSize(16777215, 16777215));
        verticalLayout_4 = new QVBoxLayout(groupBox_ELF);
        verticalLayout_4->setObjectName(QStringLiteral("verticalLayout_4"));
        widget = new QWidget(groupBox_ELF);
        widget->setObjectName(QStringLiteral("widget"));
        horizontalLayout = new QHBoxLayout(widget);
        horizontalLayout->setObjectName(QStringLiteral("horizontalLayout"));
        lab_CASign_CA = new QLabel(widget);
        lab_CASign_CA->setObjectName(QStringLiteral("lab_CASign_CA"));

        horizontalLayout->addWidget(lab_CASign_CA);

        lineEd_CASign_CA = new QLineEdit(widget);
        lineEd_CASign_CA->setObjectName(QStringLiteral("lineEd_CASign_CA"));

        horizontalLayout->addWidget(lineEd_CASign_CA);

        Btn_CASign_CA = new QPushButton(widget);
        Btn_CASign_CA->setObjectName(QStringLiteral("Btn_CASign_CA"));

        horizontalLayout->addWidget(Btn_CASign_CA);


        verticalLayout_4->addWidget(widget);

        widget_2 = new QWidget(groupBox_ELF);
        widget_2->setObjectName(QStringLiteral("widget_2"));
        horizontalLayout_8 = new QHBoxLayout(widget_2);
        horizontalLayout_8->setObjectName(QStringLiteral("horizontalLayout_8"));
        lab_CASign_elf = new QLabel(widget_2);
        lab_CASign_elf->setObjectName(QStringLiteral("lab_CASign_elf"));

        horizontalLayout_8->addWidget(lab_CASign_elf);

        treeView_CASign_elf = new QTreeView(widget_2);
        treeView_CASign_elf->setObjectName(QStringLiteral("treeView_CASign_elf"));
        treeView_CASign_elf->setMaximumSize(QSize(16777215, 16777215));

        horizontalLayout_8->addWidget(treeView_CASign_elf);


        verticalLayout_4->addWidget(widget_2);


        verticalLayout->addWidget(groupBox_ELF);

        frame_6 = new QFrame(CASign);
        frame_6->setObjectName(QStringLiteral("frame_6"));
        frame_6->setMaximumSize(QSize(16777215, 60));
        frame_6->setFrameShape(QFrame::StyledPanel);
        frame_6->setFrameShadow(QFrame::Raised);
        horizontalLayout_6 = new QHBoxLayout(frame_6);
        horizontalLayout_6->setObjectName(QStringLiteral("horizontalLayout_6"));
        horizontalSpacer = new QSpacerItem(58, 28, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_6->addItem(horizontalSpacer);

        Btn_Inport = new QPushButton(frame_6);
        Btn_Inport->setObjectName(QStringLiteral("Btn_Inport"));

        horizontalLayout_6->addWidget(Btn_Inport);

        Btn_Cancel = new QPushButton(frame_6);
        Btn_Cancel->setObjectName(QStringLiteral("Btn_Cancel"));

        horizontalLayout_6->addWidget(Btn_Cancel);


        verticalLayout->addWidget(frame_6);

        tabWidget->addTab(CASign, QString());
        RsaSign = new QWidget();
        RsaSign->setObjectName(QStringLiteral("RsaSign"));
        verticalLayout_6 = new QVBoxLayout(RsaSign);
        verticalLayout_6->setObjectName(QStringLiteral("verticalLayout_6"));
        groupBox = new QGroupBox(RsaSign);
        groupBox->setObjectName(QStringLiteral("groupBox"));
        verticalLayout_5 = new QVBoxLayout(groupBox);
        verticalLayout_5->setObjectName(QStringLiteral("verticalLayout_5"));
        widget_3 = new QWidget(groupBox);
        widget_3->setObjectName(QStringLiteral("widget_3"));
        horizontalLayout_9 = new QHBoxLayout(widget_3);
        horizontalLayout_9->setObjectName(QStringLiteral("horizontalLayout_9"));
        lab_RsaSign_rsa = new QLabel(widget_3);
        lab_RsaSign_rsa->setObjectName(QStringLiteral("lab_RsaSign_rsa"));

        horizontalLayout_9->addWidget(lab_RsaSign_rsa);

        lineEd_RsaSign_rsa = new QLineEdit(widget_3);
        lineEd_RsaSign_rsa->setObjectName(QStringLiteral("lineEd_RsaSign_rsa"));

        horizontalLayout_9->addWidget(lineEd_RsaSign_rsa);

        Btn_RsaSign_rsa = new QPushButton(widget_3);
        Btn_RsaSign_rsa->setObjectName(QStringLiteral("Btn_RsaSign_rsa"));

        horizontalLayout_9->addWidget(Btn_RsaSign_rsa);


        verticalLayout_5->addWidget(widget_3);

        widget_4 = new QWidget(groupBox);
        widget_4->setObjectName(QStringLiteral("widget_4"));
        horizontalLayout_10 = new QHBoxLayout(widget_4);
        horizontalLayout_10->setObjectName(QStringLiteral("horizontalLayout_10"));
        lab_RsaSign_elf = new QLabel(widget_4);
        lab_RsaSign_elf->setObjectName(QStringLiteral("lab_RsaSign_elf"));

        horizontalLayout_10->addWidget(lab_RsaSign_elf);

        treeView_RsaSign_elf = new QTreeView(widget_4);
        treeView_RsaSign_elf->setObjectName(QStringLiteral("treeView_RsaSign_elf"));

        horizontalLayout_10->addWidget(treeView_RsaSign_elf);


        verticalLayout_5->addWidget(widget_4);


        verticalLayout_6->addWidget(groupBox);

        frame_7 = new QFrame(RsaSign);
        frame_7->setObjectName(QStringLiteral("frame_7"));
        frame_7->setFrameShape(QFrame::StyledPanel);
        frame_7->setFrameShadow(QFrame::Raised);
        horizontalLayout_11 = new QHBoxLayout(frame_7);
        horizontalLayout_11->setObjectName(QStringLiteral("horizontalLayout_11"));
        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_11->addItem(horizontalSpacer_4);

        Btn_RsaSign_Inport = new QPushButton(frame_7);
        Btn_RsaSign_Inport->setObjectName(QStringLiteral("Btn_RsaSign_Inport"));

        horizontalLayout_11->addWidget(Btn_RsaSign_Inport);

        Btn_Rsa_Sign_Cancel = new QPushButton(frame_7);
        Btn_Rsa_Sign_Cancel->setObjectName(QStringLiteral("Btn_Rsa_Sign_Cancel"));

        horizontalLayout_11->addWidget(Btn_Rsa_Sign_Cancel);


        verticalLayout_6->addWidget(frame_7);

        tabWidget->addTab(RsaSign, QString());
        Create_Rsa = new QWidget();
        Create_Rsa->setObjectName(QStringLiteral("Create_Rsa"));
        verticalLayout_8 = new QVBoxLayout(Create_Rsa);
        verticalLayout_8->setObjectName(QStringLiteral("verticalLayout_8"));
        groupBox_4 = new QGroupBox(Create_Rsa);
        groupBox_4->setObjectName(QStringLiteral("groupBox_4"));
        horizontalLayout_12 = new QHBoxLayout(groupBox_4);
        horizontalLayout_12->setObjectName(QStringLiteral("horizontalLayout_12"));
        label = new QLabel(groupBox_4);
        label->setObjectName(QStringLiteral("label"));

        horizontalLayout_12->addWidget(label);

        Btn_GetRsa_Create_privateKey = new QPushButton(groupBox_4);
        Btn_GetRsa_Create_privateKey->setObjectName(QStringLiteral("Btn_GetRsa_Create_privateKey"));

        horizontalLayout_12->addWidget(Btn_GetRsa_Create_privateKey);

        horizontalLayout_12->setStretch(0, 1);

        verticalLayout_8->addWidget(groupBox_4);

        groupBox_3 = new QGroupBox(Create_Rsa);
        groupBox_3->setObjectName(QStringLiteral("groupBox_3"));
        gridLayout = new QGridLayout(groupBox_3);
        gridLayout->setObjectName(QStringLiteral("gridLayout"));
        gridLayout->setContentsMargins(-1, 11, -1, -1);
        lineEd_GetRsa_inport_public_privateKey = new QLineEdit(groupBox_3);
        lineEd_GetRsa_inport_public_privateKey->setObjectName(QStringLiteral("lineEd_GetRsa_inport_public_privateKey"));

        gridLayout->addWidget(lineEd_GetRsa_inport_public_privateKey, 0, 1, 1, 1);

        lab_GetRsa_inport_public_privateKey = new QLabel(groupBox_3);
        lab_GetRsa_inport_public_privateKey->setObjectName(QStringLiteral("lab_GetRsa_inport_public_privateKey"));

        gridLayout->addWidget(lab_GetRsa_inport_public_privateKey, 0, 0, 1, 1);

        Btn_GetRsa_publicKey = new QPushButton(groupBox_3);
        Btn_GetRsa_publicKey->setObjectName(QStringLiteral("Btn_GetRsa_publicKey"));

        gridLayout->addWidget(Btn_GetRsa_publicKey, 0, 2, 1, 1);

        Btn_GetRsa_Create_publicKey = new QPushButton(groupBox_3);
        Btn_GetRsa_Create_publicKey->setObjectName(QStringLiteral("Btn_GetRsa_Create_publicKey"));

        gridLayout->addWidget(Btn_GetRsa_Create_publicKey, 1, 2, 1, 1);


        verticalLayout_8->addWidget(groupBox_3);

        groupBox_2 = new QGroupBox(Create_Rsa);
        groupBox_2->setObjectName(QStringLiteral("groupBox_2"));
        verticalLayout_7 = new QVBoxLayout(groupBox_2);
        verticalLayout_7->setObjectName(QStringLiteral("verticalLayout_7"));
        widget_8 = new QWidget(groupBox_2);
        widget_8->setObjectName(QStringLiteral("widget_8"));
        horizontalLayout_18 = new QHBoxLayout(widget_8);
        horizontalLayout_18->setObjectName(QStringLiteral("horizontalLayout_18"));
        horizontalSpacer_7 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_18->addItem(horizontalSpacer_7);

        horizontalSpacer_8 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_18->addItem(horizontalSpacer_8);

        horizontalSpacer_9 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_18->addItem(horizontalSpacer_9);

        Btn_GetRsa_Create = new QPushButton(widget_8);
        Btn_GetRsa_Create->setObjectName(QStringLiteral("Btn_GetRsa_Create"));

        horizontalLayout_18->addWidget(Btn_GetRsa_Create);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_18->addItem(horizontalSpacer_5);

        Btn_GetRsa_Cancel = new QPushButton(widget_8);
        Btn_GetRsa_Cancel->setObjectName(QStringLiteral("Btn_GetRsa_Cancel"));

        horizontalLayout_18->addWidget(Btn_GetRsa_Cancel);


        verticalLayout_7->addWidget(widget_8);


        verticalLayout_8->addWidget(groupBox_2);

        verticalLayout_8->setStretch(2, 1);
        tabWidget->addTab(Create_Rsa, QString());
        Create_RootCA = new QWidget();
        Create_RootCA->setObjectName(QStringLiteral("Create_RootCA"));
        verticalLayout_2 = new QVBoxLayout(Create_RootCA);
        verticalLayout_2->setObjectName(QStringLiteral("verticalLayout_2"));
        gBox_RootCA_Inf = new QGroupBox(Create_RootCA);
        gBox_RootCA_Inf->setObjectName(QStringLiteral("gBox_RootCA_Inf"));
        gBox_RootCA_Inf->setMaximumSize(QSize(16777215, 200));
        formLayout_3 = new QFormLayout(gBox_RootCA_Inf);
        formLayout_3->setObjectName(QStringLiteral("formLayout_3"));
        lineEd_RootCountry = new QLineEdit(gBox_RootCA_Inf);
        lineEd_RootCountry->setObjectName(QStringLiteral("lineEd_RootCountry"));

        formLayout_3->setWidget(0, QFormLayout::FieldRole, lineEd_RootCountry);

        lab_RootState = new QLabel(gBox_RootCA_Inf);
        lab_RootState->setObjectName(QStringLiteral("lab_RootState"));

        formLayout_3->setWidget(1, QFormLayout::LabelRole, lab_RootState);

        lineEd_RootState = new QLineEdit(gBox_RootCA_Inf);
        lineEd_RootState->setObjectName(QStringLiteral("lineEd_RootState"));

        formLayout_3->setWidget(1, QFormLayout::FieldRole, lineEd_RootState);

        lab_RootLocality = new QLabel(gBox_RootCA_Inf);
        lab_RootLocality->setObjectName(QStringLiteral("lab_RootLocality"));

        formLayout_3->setWidget(2, QFormLayout::LabelRole, lab_RootLocality);

        lineEd_RootLocality = new QLineEdit(gBox_RootCA_Inf);
        lineEd_RootLocality->setObjectName(QStringLiteral("lineEd_RootLocality"));

        formLayout_3->setWidget(2, QFormLayout::FieldRole, lineEd_RootLocality);

        lab_RootOrganiz = new QLabel(gBox_RootCA_Inf);
        lab_RootOrganiz->setObjectName(QStringLiteral("lab_RootOrganiz"));

        formLayout_3->setWidget(3, QFormLayout::LabelRole, lab_RootOrganiz);

        lineEd_RootOrganization = new QLineEdit(gBox_RootCA_Inf);
        lineEd_RootOrganization->setObjectName(QStringLiteral("lineEd_RootOrganization"));

        formLayout_3->setWidget(3, QFormLayout::FieldRole, lineEd_RootOrganization);

        lab_RootCommon = new QLabel(gBox_RootCA_Inf);
        lab_RootCommon->setObjectName(QStringLiteral("lab_RootCommon"));

        formLayout_3->setWidget(4, QFormLayout::LabelRole, lab_RootCommon);

        lineEd_RootCommon = new QLineEdit(gBox_RootCA_Inf);
        lineEd_RootCommon->setObjectName(QStringLiteral("lineEd_RootCommon"));

        formLayout_3->setWidget(4, QFormLayout::FieldRole, lineEd_RootCommon);

        lab_RootCountry = new QLabel(gBox_RootCA_Inf);
        lab_RootCountry->setObjectName(QStringLiteral("lab_RootCountry"));

        formLayout_3->setWidget(0, QFormLayout::LabelRole, lab_RootCountry);

        lab_RootLimit = new QLabel(gBox_RootCA_Inf);
        lab_RootLimit->setObjectName(QStringLiteral("lab_RootLimit"));

        formLayout_3->setWidget(5, QFormLayout::LabelRole, lab_RootLimit);

        spinBox_RootLimit = new QSpinBox(gBox_RootCA_Inf);
        spinBox_RootLimit->setObjectName(QStringLiteral("spinBox_RootLimit"));
        spinBox_RootLimit->setMinimum(1);
        spinBox_RootLimit->setValue(30);

        formLayout_3->setWidget(5, QFormLayout::FieldRole, spinBox_RootLimit);


        verticalLayout_2->addWidget(gBox_RootCA_Inf);

        frame_2 = new QFrame(Create_RootCA);
        frame_2->setObjectName(QStringLiteral("frame_2"));
        frame_2->setMaximumSize(QSize(16777215, 60));
        frame_2->setFrameShape(QFrame::StyledPanel);
        frame_2->setFrameShadow(QFrame::Raised);
        horizontalLayout_2 = new QHBoxLayout(frame_2);
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_2);

        Btn_output_RootCA = new QPushButton(frame_2);
        Btn_output_RootCA->setObjectName(QStringLiteral("Btn_output_RootCA"));

        horizontalLayout_2->addWidget(Btn_output_RootCA);

        Btn_outClose_RootCA = new QPushButton(frame_2);
        Btn_outClose_RootCA->setObjectName(QStringLiteral("Btn_outClose_RootCA"));

        horizontalLayout_2->addWidget(Btn_outClose_RootCA);


        verticalLayout_2->addWidget(frame_2);

        tabWidget->addTab(Create_RootCA, QString());
        Create_UserCA = new QWidget();
        Create_UserCA->setObjectName(QStringLiteral("Create_UserCA"));
        verticalLayout_3 = new QVBoxLayout(Create_UserCA);
        verticalLayout_3->setObjectName(QStringLiteral("verticalLayout_3"));
        frame_3 = new QFrame(Create_UserCA);
        frame_3->setObjectName(QStringLiteral("frame_3"));
        frame_3->setFrameShape(QFrame::StyledPanel);
        frame_3->setFrameShadow(QFrame::Raised);
        horizontalLayout_3 = new QHBoxLayout(frame_3);
        horizontalLayout_3->setObjectName(QStringLiteral("horizontalLayout_3"));
        lab_User_inputRootCA = new QLabel(frame_3);
        lab_User_inputRootCA->setObjectName(QStringLiteral("lab_User_inputRootCA"));

        horizontalLayout_3->addWidget(lab_User_inputRootCA);

        lineEd_User_InputPath_RootCA = new QLineEdit(frame_3);
        lineEd_User_InputPath_RootCA->setObjectName(QStringLiteral("lineEd_User_InputPath_RootCA"));

        horizontalLayout_3->addWidget(lineEd_User_InputPath_RootCA);

        Btn_User_Visit_RootCA = new QPushButton(frame_3);
        Btn_User_Visit_RootCA->setObjectName(QStringLiteral("Btn_User_Visit_RootCA"));

        horizontalLayout_3->addWidget(Btn_User_Visit_RootCA);


        verticalLayout_3->addWidget(frame_3);

        gBox_UserCA_Inf = new QGroupBox(Create_UserCA);
        gBox_UserCA_Inf->setObjectName(QStringLiteral("gBox_UserCA_Inf"));
        formLayout_2 = new QFormLayout(gBox_UserCA_Inf);
        formLayout_2->setObjectName(QStringLiteral("formLayout_2"));
        lineEd_UserCountry = new QLineEdit(gBox_UserCA_Inf);
        lineEd_UserCountry->setObjectName(QStringLiteral("lineEd_UserCountry"));

        formLayout_2->setWidget(0, QFormLayout::FieldRole, lineEd_UserCountry);

        lab_UserState = new QLabel(gBox_UserCA_Inf);
        lab_UserState->setObjectName(QStringLiteral("lab_UserState"));

        formLayout_2->setWidget(1, QFormLayout::LabelRole, lab_UserState);

        lineEd_UserState = new QLineEdit(gBox_UserCA_Inf);
        lineEd_UserState->setObjectName(QStringLiteral("lineEd_UserState"));

        formLayout_2->setWidget(1, QFormLayout::FieldRole, lineEd_UserState);

        lab_UserLocality = new QLabel(gBox_UserCA_Inf);
        lab_UserLocality->setObjectName(QStringLiteral("lab_UserLocality"));

        formLayout_2->setWidget(2, QFormLayout::LabelRole, lab_UserLocality);

        lineEd_UserLocality = new QLineEdit(gBox_UserCA_Inf);
        lineEd_UserLocality->setObjectName(QStringLiteral("lineEd_UserLocality"));

        formLayout_2->setWidget(2, QFormLayout::FieldRole, lineEd_UserLocality);

        lab_UserOrganiz = new QLabel(gBox_UserCA_Inf);
        lab_UserOrganiz->setObjectName(QStringLiteral("lab_UserOrganiz"));

        formLayout_2->setWidget(3, QFormLayout::LabelRole, lab_UserOrganiz);

        lineEd_UserOrganization = new QLineEdit(gBox_UserCA_Inf);
        lineEd_UserOrganization->setObjectName(QStringLiteral("lineEd_UserOrganization"));

        formLayout_2->setWidget(3, QFormLayout::FieldRole, lineEd_UserOrganization);

        lab_UserCommon = new QLabel(gBox_UserCA_Inf);
        lab_UserCommon->setObjectName(QStringLiteral("lab_UserCommon"));

        formLayout_2->setWidget(4, QFormLayout::LabelRole, lab_UserCommon);

        lineEd_UserCommon = new QLineEdit(gBox_UserCA_Inf);
        lineEd_UserCommon->setObjectName(QStringLiteral("lineEd_UserCommon"));

        formLayout_2->setWidget(4, QFormLayout::FieldRole, lineEd_UserCommon);

        lab_UserCountry = new QLabel(gBox_UserCA_Inf);
        lab_UserCountry->setObjectName(QStringLiteral("lab_UserCountry"));

        formLayout_2->setWidget(0, QFormLayout::LabelRole, lab_UserCountry);

        lab_UserLimit = new QLabel(gBox_UserCA_Inf);
        lab_UserLimit->setObjectName(QStringLiteral("lab_UserLimit"));

        formLayout_2->setWidget(5, QFormLayout::LabelRole, lab_UserLimit);

        spinBox_UserLimit = new QSpinBox(gBox_UserCA_Inf);
        spinBox_UserLimit->setObjectName(QStringLiteral("spinBox_UserLimit"));
        spinBox_UserLimit->setMinimum(1);
        spinBox_UserLimit->setValue(30);

        formLayout_2->setWidget(5, QFormLayout::FieldRole, spinBox_UserLimit);


        verticalLayout_3->addWidget(gBox_UserCA_Inf);

        frame_5 = new QFrame(Create_UserCA);
        frame_5->setObjectName(QStringLiteral("frame_5"));
        frame_5->setFrameShape(QFrame::StyledPanel);
        frame_5->setFrameShadow(QFrame::Raised);
        horizontalLayout_5 = new QHBoxLayout(frame_5);
        horizontalLayout_5->setObjectName(QStringLiteral("horizontalLayout_5"));
        horizontalSpacer_3 = new QSpacerItem(246, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_5->addItem(horizontalSpacer_3);

        pushButton_2 = new QPushButton(frame_5);
        pushButton_2->setObjectName(QStringLiteral("pushButton_2"));

        horizontalLayout_5->addWidget(pushButton_2);

        pushButton = new QPushButton(frame_5);
        pushButton->setObjectName(QStringLiteral("pushButton"));

        horizontalLayout_5->addWidget(pushButton);


        verticalLayout_3->addWidget(frame_5);

        tabWidget->addTab(Create_UserCA, QString());

        verticalLayout_9->addWidget(tabWidget);

        widget_5 = new QWidget(Widget);
        widget_5->setObjectName(QStringLiteral("widget_5"));
        horizontalLayout_14 = new QHBoxLayout(widget_5);
        horizontalLayout_14->setObjectName(QStringLiteral("horizontalLayout_14"));
        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_14->addItem(horizontalSpacer_6);

        Manage_model = new QCheckBox(widget_5);
        Manage_model->setObjectName(QStringLiteral("Manage_model"));
        Manage_model->setChecked(true);

        horizontalLayout_14->addWidget(Manage_model);


        verticalLayout_9->addWidget(widget_5);

        widget_5->raise();
        tabWidget->raise();
#ifndef QT_NO_SHORTCUT
        lab_CASign_CA->setBuddy(lineEd_CASign_CA);
        lab_CASign_elf->setBuddy(treeView_CASign_elf);
        lab_RsaSign_rsa->setBuddy(lineEd_RsaSign_rsa);
        lab_RsaSign_elf->setBuddy(treeView_RsaSign_elf);
        lab_RootState->setBuddy(lineEd_UserState);
        lab_RootLocality->setBuddy(lineEd_UserLocality);
        lab_RootOrganiz->setBuddy(lineEd_UserOrganization);
        lab_RootCommon->setBuddy(lineEd_UserCommon);
        lab_RootCountry->setBuddy(lineEd_UserCountry);
        lab_User_inputRootCA->setBuddy(lineEd_User_InputPath_RootCA);
        lab_UserState->setBuddy(lineEd_UserState);
        lab_UserLocality->setBuddy(lineEd_UserLocality);
        lab_UserOrganiz->setBuddy(lineEd_UserOrganization);
        lab_UserCommon->setBuddy(lineEd_UserCommon);
        lab_UserCountry->setBuddy(lineEd_UserCountry);
#endif // QT_NO_SHORTCUT
        QWidget::setTabOrder(tabWidget, lineEd_RsaSign_rsa);
        QWidget::setTabOrder(lineEd_RsaSign_rsa, Btn_RsaSign_rsa);
        QWidget::setTabOrder(Btn_RsaSign_rsa, treeView_RsaSign_elf);
        QWidget::setTabOrder(treeView_RsaSign_elf, Btn_RsaSign_Inport);
        QWidget::setTabOrder(Btn_RsaSign_Inport, Btn_Rsa_Sign_Cancel);
        QWidget::setTabOrder(Btn_Rsa_Sign_Cancel, lineEd_CASign_CA);
        QWidget::setTabOrder(lineEd_CASign_CA, Btn_CASign_CA);
        QWidget::setTabOrder(Btn_CASign_CA, treeView_CASign_elf);
        QWidget::setTabOrder(treeView_CASign_elf, Btn_Inport);
        QWidget::setTabOrder(Btn_Inport, Btn_Cancel);
        QWidget::setTabOrder(Btn_Cancel, Manage_model);
        QWidget::setTabOrder(Manage_model, lineEd_User_InputPath_RootCA);
        QWidget::setTabOrder(lineEd_User_InputPath_RootCA, Btn_User_Visit_RootCA);
        QWidget::setTabOrder(Btn_User_Visit_RootCA, lineEd_UserCountry);
        QWidget::setTabOrder(lineEd_UserCountry, lineEd_UserState);
        QWidget::setTabOrder(lineEd_UserState, lineEd_UserLocality);
        QWidget::setTabOrder(lineEd_UserLocality, lineEd_UserOrganization);
        QWidget::setTabOrder(lineEd_UserOrganization, lineEd_UserCommon);
        QWidget::setTabOrder(lineEd_UserCommon, pushButton_2);
        QWidget::setTabOrder(pushButton_2, pushButton);
        QWidget::setTabOrder(pushButton, lineEd_RootCountry);
        QWidget::setTabOrder(lineEd_RootCountry, lineEd_RootState);
        QWidget::setTabOrder(lineEd_RootState, lineEd_RootLocality);
        QWidget::setTabOrder(lineEd_RootLocality, lineEd_RootOrganization);
        QWidget::setTabOrder(lineEd_RootOrganization, lineEd_RootCommon);
        QWidget::setTabOrder(lineEd_RootCommon, Btn_output_RootCA);
        QWidget::setTabOrder(Btn_output_RootCA, Btn_outClose_RootCA);

        retranslateUi(Widget);
        QObject::connect(Btn_Cancel, SIGNAL(clicked()), Widget, SLOT(close()));

        tabWidget->setCurrentIndex(4);


        QMetaObject::connectSlotsByName(Widget);
    } // setupUi

    void retranslateUi(QWidget *Widget)
    {
        Widget->setWindowTitle(QApplication::translate("Widget", "kEIPM", Q_NULLPTR));
        groupBox_ELF->setTitle(QApplication::translate("Widget", "\345\257\274\345\205\245\350\257\201\344\271\246\344\273\245\347\255\276\345\220\215ELF\346\226\207\344\273\266:", Q_NULLPTR));
        lab_CASign_CA->setText(QApplication::translate("Widget", "\347\224\250\346\210\267\350\257\201\344\271\246", Q_NULLPTR));
        Btn_CASign_CA->setText(QApplication::translate("Widget", "\346\265\217\350\247\210", Q_NULLPTR));
        lab_CASign_elf->setText(QApplication::translate("Widget", "ELF\346\226\207\344\273\266:", Q_NULLPTR));
        Btn_Inport->setText(QApplication::translate("Widget", "\347\255\276\345\220\215", Q_NULLPTR));
        Btn_Cancel->setText(QApplication::translate("Widget", "\351\200\200\345\207\272", Q_NULLPTR));
        tabWidget->setTabText(tabWidget->indexOf(CASign), QApplication::translate("Widget", "\350\257\201\344\271\246\347\255\276\345\220\215", Q_NULLPTR));
        groupBox->setTitle(QApplication::translate("Widget", "\345\257\274\345\205\245\347\247\201\351\222\245\344\273\245\347\255\276\345\220\215ELF\346\226\207\344\273\266:", Q_NULLPTR));
        lab_RsaSign_rsa->setText(QApplication::translate("Widget", "PEM\347\247\201\351\222\245:", Q_NULLPTR));
        Btn_RsaSign_rsa->setText(QApplication::translate("Widget", "\346\265\217\350\247\210", Q_NULLPTR));
        lab_RsaSign_elf->setText(QApplication::translate("Widget", "ELF\346\226\207\344\273\266:", Q_NULLPTR));
        Btn_RsaSign_Inport->setText(QApplication::translate("Widget", "\347\255\276\345\220\215", Q_NULLPTR));
        Btn_Rsa_Sign_Cancel->setText(QApplication::translate("Widget", "\351\200\200\345\207\272", Q_NULLPTR));
        tabWidget->setTabText(tabWidget->indexOf(RsaSign), QApplication::translate("Widget", "\347\247\201\351\222\245\347\255\276\345\220\215", Q_NULLPTR));
        groupBox_4->setTitle(QApplication::translate("Widget", "\347\224\237\346\210\220PEM\347\247\201\351\222\245", Q_NULLPTR));
        label->setText(QString());
        Btn_GetRsa_Create_privateKey->setText(QApplication::translate("Widget", "\347\224\237\346\210\220", Q_NULLPTR));
        groupBox_3->setTitle(QApplication::translate("Widget", "\345\257\274\345\205\245PEM\347\247\201\351\222\245\344\273\245\346\217\220\345\217\226\345\205\254\351\222\245", Q_NULLPTR));
        lab_GetRsa_inport_public_privateKey->setText(QApplication::translate("Widget", "\345\257\274\345\205\245\347\247\201\351\222\245", Q_NULLPTR));
        Btn_GetRsa_publicKey->setText(QApplication::translate("Widget", "\346\265\217\350\247\210", Q_NULLPTR));
        Btn_GetRsa_Create_publicKey->setText(QApplication::translate("Widget", "\347\224\237\346\210\220", Q_NULLPTR));
        groupBox_2->setTitle(QApplication::translate("Widget", "\344\270\200\351\224\256\347\224\237\346\210\220\345\257\206\351\222\245\345\257\271", Q_NULLPTR));
        Btn_GetRsa_Create->setText(QApplication::translate("Widget", "\344\270\200\351\224\256\347\224\237\346\210\220", Q_NULLPTR));
        Btn_GetRsa_Cancel->setText(QApplication::translate("Widget", "\351\200\200\345\207\272", Q_NULLPTR));
        tabWidget->setTabText(tabWidget->indexOf(Create_Rsa), QApplication::translate("Widget", "\347\224\237\346\210\220\345\205\254\347\247\201\351\222\245", Q_NULLPTR));
        gBox_RootCA_Inf->setTitle(QApplication::translate("Widget", "\350\257\267\350\276\223\345\205\245\347\255\276\345\220\215\344\277\241\346\201\257:", Q_NULLPTR));
        lineEd_RootCountry->setPlaceholderText(QApplication::translate("Widget", "Country Name (2 letter code)", Q_NULLPTR));
        lab_RootState->setText(QApplication::translate("Widget", "S \346\211\200\345\234\250\347\234\201\344\273\275 (State/Provice)", Q_NULLPTR));
        lineEd_RootState->setPlaceholderText(QApplication::translate("Widget", "State or Province Name (full name)", Q_NULLPTR));
        lab_RootLocality->setText(QApplication::translate("Widget", "L \346\211\200\345\234\250\345\237\216\345\270\202 (Locality)", Q_NULLPTR));
        lineEd_RootLocality->setPlaceholderText(QApplication::translate("Widget", "Locality Name (eg, city)", Q_NULLPTR));
        lab_RootOrganiz->setText(QApplication::translate("Widget", "O \345\215\225\344\275\215\345\220\215\347\247\260 (Organization Name)", Q_NULLPTR));
        lineEd_RootOrganization->setPlaceholderText(QApplication::translate("Widget", "Organization Name (eg, company)", Q_NULLPTR));
        lab_RootCommon->setText(QApplication::translate("Widget", "CN \345\205\254\347\224\250\345\220\215\347\247\260 (Common Name)", Q_NULLPTR));
        lineEd_RootCommon->setPlaceholderText(QApplication::translate("Widget", "Common Name (e.g. server FQDN or YOUR name)", Q_NULLPTR));
        lab_RootCountry->setText(QApplication::translate("Widget", "C \346\211\200\345\234\250\345\233\275\345\256\266 (Country)", Q_NULLPTR));
        lab_RootLimit->setText(QApplication::translate("Widget", "\350\257\201\344\271\246\346\234\211\346\225\210\346\234\237(/\345\244\251\357\274\211", Q_NULLPTR));
        Btn_output_RootCA->setText(QApplication::translate("Widget", "\347\224\237\346\210\220", Q_NULLPTR));
        Btn_outClose_RootCA->setText(QApplication::translate("Widget", "\351\200\200\345\207\272", Q_NULLPTR));
        tabWidget->setTabText(tabWidget->indexOf(Create_RootCA), QApplication::translate("Widget", "\347\224\237\346\210\220CA\350\257\201\344\271\246", Q_NULLPTR));
        lab_User_inputRootCA->setText(QApplication::translate("Widget", "\345\257\274\345\205\245CA\345\217\212\347\247\201\351\222\245", Q_NULLPTR));
        Btn_User_Visit_RootCA->setText(QApplication::translate("Widget", "\346\265\217\350\247\210", Q_NULLPTR));
        gBox_UserCA_Inf->setTitle(QApplication::translate("Widget", "\350\257\267\350\276\223\345\205\245\347\255\276\345\220\215\344\277\241\346\201\257\357\274\232", Q_NULLPTR));
        lineEd_UserCountry->setPlaceholderText(QApplication::translate("Widget", "Country Name (2 letter code)", Q_NULLPTR));
        lab_UserState->setText(QApplication::translate("Widget", "S \346\211\200\345\234\250\347\234\201\344\273\275 (State/Provice)", Q_NULLPTR));
        lineEd_UserState->setPlaceholderText(QApplication::translate("Widget", "State or Province Name (full name)", Q_NULLPTR));
        lab_UserLocality->setText(QApplication::translate("Widget", "L \346\211\200\345\234\250\345\237\216\345\270\202 (Locality)", Q_NULLPTR));
        lineEd_UserLocality->setPlaceholderText(QApplication::translate("Widget", "Locality Name (eg, city)", Q_NULLPTR));
        lab_UserOrganiz->setText(QApplication::translate("Widget", "O \345\215\225\344\275\215\345\220\215\347\247\260 (Organization Name)", Q_NULLPTR));
        lineEd_UserOrganization->setPlaceholderText(QApplication::translate("Widget", "Organization Name (eg, company)", Q_NULLPTR));
        lab_UserCommon->setText(QApplication::translate("Widget", "CN \345\205\254\347\224\250\345\220\215\347\247\260 (Common Name)", Q_NULLPTR));
        lineEd_UserCommon->setPlaceholderText(QApplication::translate("Widget", "Common Name (e.g. server FQDN or YOUR name)", Q_NULLPTR));
        lab_UserCountry->setText(QApplication::translate("Widget", "C \346\211\200\345\234\250\345\233\275\345\256\266 (Country)", Q_NULLPTR));
        lab_UserLimit->setText(QApplication::translate("Widget", "\350\257\201\344\271\246\346\234\211\346\225\210\346\234\237(/\345\244\251\357\274\211", Q_NULLPTR));
        pushButton_2->setText(QApplication::translate("Widget", "\347\224\237\346\210\220", Q_NULLPTR));
        pushButton->setText(QApplication::translate("Widget", "\351\200\200\345\207\272", Q_NULLPTR));
        tabWidget->setTabText(tabWidget->indexOf(Create_UserCA), QApplication::translate("Widget", "\347\224\237\346\210\220\347\224\250\346\210\267\350\257\201\344\271\246", Q_NULLPTR));
        Manage_model->setText(QApplication::translate("Widget", "\347\256\241\347\220\206\345\221\230\346\250\241\345\274\217", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class Widget: public Ui_Widget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WIDGET_H
