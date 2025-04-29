"""
模块功能: GUI
作者: W啥都学
创建日期: 2025-02-25
修改时间：2025-04-28
"""

__author__ = "W啥都学"

import csv
import json
import asyncio
import os
import queue
import subprocess
import sys
import threading
import time
from urllib.parse import unquote
import ai_analysis_core
import requests
import yaml
import module
from PyQt6.QtPrintSupport import QPrinter

import replay_request
import re
import session_utils
from urllib.parse import urlparse
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QMarginsF, QRegularExpression, QDateTime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QMessageBox, QTextEdit,
                             QLineEdit, QCheckBox, QFileDialog, QVBoxLayout, QHBoxLayout,
                             QGridLayout, QGroupBox, QWidget, QTabWidget, QProgressBar,
                             QLabel, QRadioButton, QSplitter, QFrame, QTableWidget,
                             QTableWidgetItem, QListWidget, QListWidgetItem, QToolBar,
                             QStatusBar, QToolButton, QMenu, QSizePolicy, QFormLayout, QProgressDialog, QComboBox,
                             QInputDialog, QHeaderView, QAbstractItemView, QGraphicsDropShadowEffect, QScrollArea,
                             QToolTip)
from PyQt6.QtGui import (QIcon, QPixmap, QTextCursor, QTextCharFormat, QColor,
                         QPainter, QFont, QAction, QPalette, QTextDocument, QPageLayout, QPageSize, QSyntaxHighlighter,
                         QBrush, QCursor)
from PyQt6.QtCharts import QChartView, QChart, QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis, \
    QLineSeries, QDateTimeAxis, QCategoryAxis

import pyshark
import core_processing
import output_filtering
from collections import defaultdict
import datetime
import webbrowser
from log_parsing import log_identification
from binary_extraction import load_signatures, extract_file

version = "0.0.4"

last_updated = "2025-04-20"

# 设置代理
proxies = None

INITIALIZATION = defaultdict(lambda: {
            'count': 0,
            'status_codes': defaultdict(int),
            'source_ips': defaultdict(int),
            'methods': defaultdict(int),
            'request_time': defaultdict(int),
            'UA': defaultdict(int),
            "danger": defaultdict(int),
        })

FULL_DATA = []


class LogProcessingThread(QThread):
    finished = pyqtSignal(dict, object)  # 处理完成信号
    error = pyqtSignal(str)      # 错误信号
    progress = pyqtSignal(int)   # 进度信号(可选)

    def __init__(self, file_path, log_type,url_stats,ai_analysis_starts):
        super().__init__()
        self.file_path = file_path
        self.log_type = log_type
        self.url_stats = url_stats
        self.ai_analysis_starts = ai_analysis_starts # 判断ai分析

    def run(self):

        log_identification.process_log_file(self.file_path, self.url_stats, self.log_type)
        self.finished.emit(self.url_stats,self.ai_analysis_starts)





class AIAnalysisThread(QThread):
    """AI分析线程"""
    result_signal = pyqtSignal(str)
    update_content = pyqtSignal(str)
    finished_signal = pyqtSignal(str)

    def __init__(self, model_type, analysis_data, config, traffic_type):
        super().__init__()
        self.model_type = model_type
        self.analysis_data = analysis_data  # 要分析的数据
        self.traffic_type = traffic_type  # 流量类型
        self.config = config
        self.stop_flag = False

    def run(self):
        """执行AI分析"""

        if self.model_type.startswith("本地模型"):
            self.analyze_with_local_model()
        elif self.model_type == "DeepSeek":
            self.analyze_with_deepseek()
        elif self.model_type == "OpenAI":
            self.analyze_with_openai()
        elif self.model_type == "Gemini":
            self.analyze_with_gemini()

        # self.finished_signal.emit("分析完成")

    def analyze_with_local_model(self):
        """使用本地Ollama模型分析"""
        ollama_config = self.config.get('ollama', {})
        api_url = f"{ollama_config.get('url')}/api/generate"
        model_name = ollama_config.get('model_name')
        for prompt in self.analysis_data:
            self.update_content.emit(prompt)
            try:
                response = requests.post(
                    api_url,
                    json={
                        "model": model_name,
                        "prompt": prompt,
                        "stream": True
                    },
                    stream=True,
                    timeout=60
                )
                for line in response.iter_lines():
                    if self.stop_flag:
                        break
                    if line:
                        try:
                            data = json.loads(line.decode())
                            if "response" in data:
                                self.result_signal.emit(data["response"])
                        except:
                            continue
            except requests.exceptions.RequestException as e:
                self.finished_signal.emit(f"连接本地模型失败")
                return
                # self.result_signal.emit(f"\n连接本地模型失败: {str(e)}")
        self.finished_signal.emit(f"AI分析完成")

    def analyze_with_deepseek(self):
        """使用DeepSeek API分析"""
        api_key = self.config.get('deepseek_api_key', '')
        if not api_key:
            self.result_signal.emit("\nDeepSeek API密钥未配置!")
            return

        prompt = self.build_prompt()
        self.result_signal.emit("\nDeepSeek分析功能正在开发中...")

    def analyze_with_openai(self):
        """使用OpenAI API分析"""
        api_key = self.config.get('openai_api_key', '')
        if not api_key:
            self.result_signal.emit("\nOpenAI API密钥未配置!")
            return

        prompt = self.build_prompt()
        self.result_signal.emit("\nOpenAI分析功能正在开发中...")

    def stop(self):
        """停止分析"""
        self.stop_flag = True
class FullscreenWindow(QMainWindow):
    def __init__(self, widget, title, manager):
        super().__init__(manager.parent)
        self.manager = manager
        self.widget = widget
        self.setWindowTitle(title)
        self.setWindowFlags(Qt.WindowType.Window)
        # 工具栏退出按钮
        toolbar = QToolBar("全屏工具栏", self)
        exit_action = QAction(QIcon("ico/exit_fullscreen.png"), "退出全屏", self)
        exit_action.triggered.connect(self.manager.exit_fullscreen)
        toolbar.addAction(exit_action)
        self.addToolBar(toolbar)
        # 中央显示区域
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        self.setCentralWidget(central)

    def closeEvent(self, event):
        # 确保点击×也退出全屏并回归原位
        self.manager.exit_fullscreen()
        super().closeEvent(event)

class FullscreenManager:
    def __init__(self, parent):
        self.parent = parent
        self.fullscreen_widget = None
        self.fullscreen_window = None
        self.original_layout = None

    def enter_fullscreen(self, widget, title):
        """进入全屏模式"""
        if self.fullscreen_widget:
            return

        self.fullscreen_widget = widget
        # 保存原父布局
        self.original_layout = widget.parent().layout()
        self.original_layout.removeWidget(widget)

        # 创建并显示全屏窗口
        self.fullscreen_window = FullscreenWindow(widget, title, self)
        self.fullscreen_window.showMaximized()

    def exit_fullscreen(self):
        """退出全屏模式"""
        if not self.fullscreen_widget:
            return

        # 从全屏窗口移除控件
        self.fullscreen_window.centralWidget().layout().removeWidget(self.fullscreen_widget)

        # 将控件返回原布局
        self.original_layout.addWidget(self.fullscreen_widget)

        # 关闭全屏窗口
        self.fullscreen_window.close()

        # 清理状态
        self.fullscreen_widget = None
        self.fullscreen_window = None
        self.original_layout = None
class RegexHighlighter(QSyntaxHighlighter):
    """正则表达式语法高亮"""

    def __init__(self, document):
        super().__init__(document)

        self.highlightingRules = []

        # 元字符
        meta_format = QTextCharFormat()
        meta_format.setForeground(QColor("#FF6600"))
        meta_format.setFontWeight(QFont.Weight.Bold)
        meta_chars = r"[\.\^\$\*\+\?\{\}\[\]\\\|\(\)]"
        self.highlightingRules.append((QRegularExpression(meta_chars), meta_format))

        # 字符类
        char_class_format = QTextCharFormat()
        char_class_format.setForeground(QColor("#0099FF"))
        self.highlightingRules.append((QRegularExpression(r"\[.*?\]"), char_class_format))

        # 量词
        quantifier_format = QTextCharFormat()
        quantifier_format.setForeground(QColor("#9900FF"))
        quantifiers = r"\*|\+|\?|\{\d+,?\d*\}"
        self.highlightingRules.append((QRegularExpression(quantifiers), quantifier_format))

        # 分组
        group_format = QTextCharFormat()
        group_format.setForeground(QColor("#00AA00"))
        self.highlightingRules.append((QRegularExpression(r"\(.*?\)"), group_format))

        # 转义序列
        escape_format = QTextCharFormat()
        escape_format.setForeground(QColor("#FF0000"))
        self.highlightingRules.append((QRegularExpression(r"\\."), escape_format))

        # 注释
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#999999"))
        comment_format.setFontItalic(True)
        self.highlightingRules.append((QRegularExpression(r"#.*$"), comment_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlightingRules:
            iterator = pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)


class AnalysisThread(QThread):
    result_signal = pyqtSignal(str)  # 结果信号
    result_signal_extract = pyqtSignal(dict)  # 文件提取
    handle_replay_response = pyqtSignal(str)  # 结果信号
    status_label = pyqtSignal(str)  # 结果信号
    finished_signal = pyqtSignal(object)  # 可以传如何参数
    request_found_signal = pyqtSignal()  # 任务完成信号
    progress_signal = pyqtSignal(int)  # 进度信号

    def __init__(self, file, uri, keyword, output, request_only,
                 response_only, show_body, request_stream_id=None,
                 sslkeylogfile=None, fileextraction=None,
                 ai_analysis_starts=None):
        super().__init__()
        self.result_cache = []
        self.file = file
        self.uri = uri
        self.keyword = keyword
        self.output = output
        self.request_only = request_only
        self.response_only = response_only
        self.show_body = show_body
        self.ai_analysis_storing_data = ai_analysis_starts  # AI 分析 会记录全部的请求响应数据
        self.sslkeylogfile = sslkeylogfile  # 追加的 SSL 密钥日志文件路径
        self.request_stream_id = request_stream_id
        self.fileextraction = fileextraction
        # if self.fileextraction:  # 判断是否文件读取
        self.result_queue = queue.Queue()
        self._send_thread = threading.Thread(target=self._emit_loop, daemon=True)
        self._send_thread.start()
        self.last_result = None
        self.analysis_similar = "pyshark"  # 默认使用pyshark

    def _emit_loop(self):
        """后台发送线程，专门负责发 result_signal"""
        while True:
            try:
                msg = self.result_queue.get(timeout=1)
                self.result_signal.emit(msg)
                time.sleep(0.01)  # 控制一下发送频率，防止挤爆 UI
            except queue.Empty:
                continue

    def data_processing(self, result):
        if self.request_stream_id is not None and result['stream_id'] == self.request_stream_id and "Request" == result['http_type']:
            self.result_queue.put("构建发送请求数据: \n" + output_filtering.complete_data(result) + "\n响应数据:")
            self.result_queue.put(replay_request.build_send(result, proxies))
        elif self.filter_result(result) and self.request_stream_id is None:
            self.result_queue.put(output_filtering.visual_output(result, self.show_body))

    def file_extraction(self, result):
        """ 文件提取模块 """
        config_path = "config.yaml"
        hex_data = result['file_data']
        os.makedirs(self.fileextraction['save_path'], exist_ok=True)
        signatures = load_signatures(config_path, self.fileextraction['file_filter'])
        result = extract_file(hex_data, signatures, self.fileextraction['save_path'], result['uri'])
        if result['filename']:
            self.result_signal_extract.emit(result)
        else:
            print("未识别到文件")

    def run_tshark_analysis(self):
        """使用tshark进行分析"""
        session_data = []
        url_count = defaultdict(lambda: {
            'count': 0,
            'status_codes': defaultdict(int),
            'source_ips': defaultdict(int),
            'methods': defaultdict(int),
            'request_time': defaultdict(int),
            'UA': defaultdict(int),
            "danger": defaultdict(int),
        })

        # 创建并设置新的事件循环
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        process = core_processing.based_on_tshark(self.file, self.sslkeylogfile)


        for line in process.stdout:

            result = core_processing.process_tshark_line(line, url_count, session_data=session_data)
            if self.fileextraction and result['file_data']:  # 判断是否文件读取
                self.file_extraction(result)
                try:
                    self.status_label.emit("探测数据：" + str(bytes.fromhex(result['file_data'])[:60]) + ".......")
                except:
                    pass

            if self.ai_analysis_storing_data and "Request" == result['http_type']:  # AI分析会记录全部的请求数据
                self.ai_analysis_storing_data["request"]['all'].append(result)

            self.data_processing(result)

        self.last_result = url_count

    def run_pyshark_analysis(self):
        """使用pyshark进行分析"""
        url_count = defaultdict(lambda: {
            'count': 0,
            'status_codes': defaultdict(int),
            'source_ips': defaultdict(int),
            'methods': defaultdict(int),
            'request_time': defaultdict(int),
            'UA': defaultdict(int),
            "danger": defaultdict(int),
        })
        session_data = []

        # 创建并设置新的事件循环
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        sslkeylogfile = None
        if self.sslkeylogfile:  # 如果提供了 SSL 密钥日志文件
            sslkeylogfile = {'tls.keylog_file': self.sslkeylogfile}

        cap = pyshark.FileCapture(
            self.file,
            display_filter='http || http2',
            override_prefs=sslkeylogfile
        )

        # total_packets = len(cap)
        # processed_packets = 0

        for index, pkt in enumerate(cap, start=0):

            result = core_processing.core_processing(pkt, url_count, session_data=session_data)
            if self.fileextraction and result['file_data']:  # 判断是否文件读取

                self.file_extraction(result)
                try:
                    self.status_label.emit("探测数据：" + str(bytes.fromhex(result['file_data'])[:60]) + ".......")
                except:
                    pass
            if self.ai_analysis_storing_data and "Request" == result['http_type']:  # AI分析会记录全部的请求数据
                self.ai_analysis_storing_data["request"]['all'].append(result)

            self.data_processing(result)
            # processed_packets += 1
            # progress = int((processed_packets / total_packets) * 100) if total_packets > 0 else 0
            # self.progress_signal.emit(progress)

        self.last_result = url_count

    def filter_result(self, result):
        """根据参数过滤结果"""
        if not result:
            return False
        # 请求/响应过滤
        if self.request_only and result['http_type'] != 'Request':
            return False
        if self.response_only and result['http_type'] != 'Response':
            return False

        # URI过滤
        if self.uri and self.uri not in result['url']:
            return False

        # 关键字过滤
        if self.keyword and self.keyword not in output_filtering.visual_output(result, self.show_body):
            return False

        return True

    def run(self):
        """运行流量分析"""
        self.result_signal.emit(f"开始分析，使用方式: {self.analysis_similar}")

        # 初始化
        if self.ai_analysis_storing_data:
            self.ai_analysis_storing_data["request"]['all'] = []

        print(f"开始分析，使用方式: {self.analysis_similar}")
        if self.analysis_similar == "tshark":
            self.run_tshark_analysis()
        else:
            self.run_pyshark_analysis()

        if self.ai_analysis_storing_data:  # AI分析判断
            self.finished_signal.emit(self.ai_analysis_storing_data)
        else:
            self.finished_signal.emit(None)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TrafficEye - WEB网络流量分析工具 -研发版  ——作者：W啥都学")
        self.setMinimumSize(1600, 900)

        self.ai_analysis_pending = False  # 添加状态标志
        self.ai_analysis_in_progress = False  # 添加进行中标志
        self.run_ai = False

        # 设置应用图标
        self.setWindowIcon(QIcon("ico/l.png"))

        # 初始化UI
        self.init_ui()

        # 初始化统计数据结构
        self.url_stats = defaultdict(lambda: {
            'count': 0,
            'status_codes': defaultdict(int),
            'source_ips': defaultdict(int),
            'methods': defaultdict(int),
            'request_time': defaultdict(int),
            'UA': defaultdict(int),
            "danger": defaultdict(int),
        })

        # 分析线程
        self.analysis_thread = None
        self.replay_thread = None

    def init_ui(self):
        """初始化主界面"""
        # 设置主窗口样式
        self.setStyleSheet(self.get_main_stylesheet())
        # 加载初始配置
        self.config=module.load_config()



        # 创建菜单栏
        self.create_menu_bar()

        # 创建工具栏
        self.create_tool_bar()

        # 创建主内容区域
        self.create_main_content()

        # 创建状态栏
        self.create_status_bar()
        # 创建报告
        self.create_report_tab()
        self.create_settings_tab()
        # 设置中央部件
        central_widget = QWidget()
        central_widget.setLayout(QVBoxLayout())
        central_widget.layout().setContentsMargins(0, 0, 0, 0)
        central_widget.layout().setSpacing(0)
        central_widget.layout().addWidget(self.main_content)
        self.setCentralWidget(central_widget)

    def get_main_stylesheet(self):
        """返回主样式表"""
        return """
            QToolTip {
                background-color: #2D2D2D;
                color: #FFFFFF;
                border: 1px solid #0078D7;
                padding: 5px;
                border-radius: 5px;
                font-size: 12px;
            }
            QMainWindow {
                background-color: #2D2D2D;
            }
            QWidget {
                color: #E0E0E0;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                border-radius: 4px;
                padding: 4px;
                background: #3A3A3A;
            }
            QTextEdit, QLineEdit {
                background-color: #252525;
                color: #EEE;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 5px;
                font-family: Consolas, Courier New, monospace;
                font-size: 12px;
            }
            QPushButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #5A5A5A;
            }
            QPushButton:pressed {
                background-color: #3A3A3A;
            }
            QPushButton:disabled {
                background-color: #333;
                color: #777;
            }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
                background: #3A3A3A;
                color: white;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }

            QProgressBar {
                border: 1px solid #444;
                border-radius: 4px;
                text-align: center;
                background: #252525;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
            QLabel {
                color: white;
            }
            QTableWidget {
                background-color: #252525;
                color: #EEE;
                gridline-color: #444;
                border: 1px solid #444;
            }
            QHeaderView::section {
                background-color: #3A3A3A;
                color: white;
                padding: 5px;
                border: 1px solid #444;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #4A6EA9;
            }
            QMenuBar {
                background-color: #3A3A3A;
                color: white;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 5px 10px;
            }
            QMenuBar::item:selected {
                background-color: #5A5A5A;
            }
            QMenu {
                background-color: #3A3A3A;
                border: 1px solid #444;
                color: white;
            }
            QMenu::item:selected {
                background-color: #5A5A5A;
            }
            QToolBar {
                background-color: #3A3A3A;
                border: none;
                spacing: 5px;
                padding: 5px;
            }
            QToolButton {
                padding: 5px;
            }
            QStatusBar {
                background-color: #3A3A3A;
                color: white;
            }
            QSplitter::handle {
                background: #3E3E3E;
            }
        """
    # def get_main_stylesheet(self):
    #     """返回主样式表"""
    #     return """
    #     /* 主窗口样式 */
    #     QMainWindow {
    #         background-color: #2D2D2D;
    #     }
    #
    #     /* 全局字体和颜色 */
    #     QWidget {
    #         color: #E0E0E0;
    #         font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
    #         font-size: 13px;
    #     }
    #
    #     /* 按钮样式 */
    #     QPushButton {
    #         background-color: #3A3A3A;
    #         color: white;
    #         border: 1px solid #4A4A4A;
    #         border-radius: 4px;
    #         padding: 6px 12px;
    #         min-width: 80px;
    #     }
    #     QPushButton:hover {
    #         background-color: #4A4A4A;
    #         border: 1px solid #5A5A5A;
    #     }
    #     QPushButton:pressed {
    #         background-color: #2A2A2A;
    #     }
    #     QPushButton:disabled {
    #         background-color: #333333;
    #         color: #777777;
    #     }
    #
    #     /* 输入框样式 */
    #     QLineEdit, QTextEdit {
    #         background-color: #252525;
    #         color: #EEE;
    #         border: 1px solid #444;
    #         border-radius: 4px;
    #         padding: 5px;
    #     }
    #
    #     /* 复选框样式 */
    #     QCheckBox::indicator {
    #         width: 16px;
    #         height: 16px;
    #     }
    #     QCheckBox::indicator:unchecked {
    #         border: 1px solid #777;
    #         background: #333;
    #     }
    #     QCheckBox::indicator:checked {
    #         border: 1px solid #0078D7;
    #         background: #0078D7;
    #     }
    #
    #     /* 单选按钮样式 */
    #     QRadioButton::indicator {
    #         width: 16px;
    #         height: 16px;
    #         border-radius: 8px;
    #     }
    #     QRadioButton::indicator:unchecked {
    #         border: 1px solid #777;
    #         background: #333;
    #     }
    #     QRadioButton::indicator:checked {
    #         border: 1px solid #0078D7;
    #         background: #0078D7;
    #     }
    #
    #     /* 选项卡样式 */
    #     QTabWidget::pane {
    #         border: 1px solid #444;
    #         border-radius: 4px;
    #         background: #3A3A3A;
    #     }
    #     QTabBar::tab {
    #         background: #3A3A3A;
    #         color: #AAA;
    #         padding: 8px 15px;
    #         border: 1px solid #444;
    #         border-bottom: none;
    #         border-top-left-radius: 4px;
    #         border-top-right-radius: 4px;
    #     }
    #     QTabBar::tab:selected {
    #         background: #252525;
    #         color: white;
    #         border-bottom: 2px solid #0078D7;
    #     }
    #     QTabBar::tab:hover {
    #         background: #4A4A4A;
    #     }
    #
    #     /* 表格样式 */
    #     QTableWidget {
    #         background-color: #252525;
    #         color: #EEE;
    #         gridline-color: #444;
    #         border: 1px solid #444;
    #     }
    #     QHeaderView::section {
    #         background-color: #3A3A3A;
    #         color: white;
    #         padding: 5px;
    #         border: 1px solid #444;
    #     }
    #     QTableWidget::item {
    #         padding: 5px;
    #     }
    #     QTableWidget::item:selected {
    #         background-color: #4A6EA9;
    #     }
    #
    #     /* 菜单栏样式 */
    #     QMenuBar {
    #         background-color: #3A3A3A;
    #         color: white;
    #     }
    #     QMenuBar::item {
    #         padding: 5px 10px;
    #         background: transparent;
    #     }
    #     QMenuBar::item:selected {
    #         background: #5A5A5A;
    #     }
    #     QMenu {
    #         background-color: #3A3A3A;
    #         border: 1px solid #444;
    #         color: white;
    #     }
    #     QMenu::item:selected {
    #         background-color: #5A5A5A;
    #     }
    #
    #     /* 工具栏样式 */
    #     QToolBar {
    #         background-color: #3A3A3A;
    #         border: none;
    #         spacing: 5px;
    #         padding: 5px;
    #     }
    #     QToolButton {
    #         padding: 5px;
    #     }
    #
    #     /* 状态栏样式 */
    #     QStatusBar {
    #         background-color: #3A3A3A;
    #         color: white;
    #     }
    #
    #     /* 分割线样式 */
    #     QSplitter::handle {
    #         background: #3E3E3E;
    #     }
    #
    #     /* 进度条样式 */
    #     QProgressBar {
    #         border: 1px solid #555;
    #         border-radius: 3px;
    #         text-align: center;
    #         background: #252525;
    #     }
    #     QProgressBar::chunk {
    #         background-color: #4CAF50;
    #         width: 10px;
    #     }
    # """

    def create_menu_bar(self):
        """创建菜单栏"""
        menubar = self.menuBar()

        # # 文件菜单
        # file_menu = menubar.addMenu("文件")
        #
        # new_action = QAction(QIcon("ico/new.png"), "新建项目", self)
        # new_action.setShortcut("Ctrl+N")
        # file_menu.addAction(new_action)
        #
        # open_action = QAction(QIcon("ico/open.png"), "打开...", self)
        # open_action.setShortcut("Ctrl+O")
        # open_action.triggered.connect(self.select_file)
        # file_menu.addAction(open_action)
        #
        # save_action = QAction(QIcon("ico/save.png"), "保存", self)
        # save_action.setShortcut("Ctrl+S")
        # file_menu.addAction(save_action)
        #
        # file_menu.addSeparator()
        #
        # export_menu = file_menu.addMenu(QIcon("ico/export.png"), "导出")
        # export_text_action = QAction("导出为文本", self)
        # export_text_action.triggered.connect(self.export_results)
        # export_csv_action = QAction("导出为CSV", self)
        # export_csv_action.triggered.connect(self.export_stats)
        # export_pdf_action = QAction("导出为PDF", self)
        # export_menu.addAction(export_text_action)
        # export_menu.addAction(export_csv_action)
        # export_menu.addAction(export_pdf_action)
        #
        # file_menu.addSeparator()
        #
        # exit_action = QAction(QIcon("ico/exit.png"), "退出", self)
        # exit_action.setShortcut("Ctrl+Q")
        # exit_action.triggered.connect(self.close)
        # file_menu.addAction(exit_action)
        #
        # # 编辑菜单
        # edit_menu = menubar.addMenu("编辑")
        #
        # undo_action = QAction(QIcon("ico/undo.png"), "撤销", self)
        # undo_action.setShortcut("Ctrl+Z")
        # edit_menu.addAction(undo_action)
        #
        # redo_action = QAction(QIcon("ico/redo.png"), "重做", self)
        # redo_action.setShortcut("Ctrl+Y")
        # edit_menu.addAction(redo_action)
        #
        # edit_menu.addSeparator()
        #
        # cut_action = QAction(QIcon("ico/cut.png"), "剪切", self)
        # cut_action.setShortcut("Ctrl+X")
        # edit_menu.addAction(cut_action)
        #
        # copy_action = QAction(QIcon("ico/copy.png"), "复制", self)
        # copy_action.setShortcut("Ctrl+C")
        # edit_menu.addAction(copy_action)
        #
        # paste_action = QAction(QIcon("ico/paste.png"), "粘贴", self)
        # paste_action.setShortcut("Ctrl+V")
        # edit_menu.addAction(paste_action)

        # 视图菜单
        view_menu = menubar.addMenu("视图")

        toolbar_action = QAction("工具栏", self)
        toolbar_action.setCheckable(True)
        toolbar_action.setChecked(True)
        toolbar_action.triggered.connect(self.toggle_toolbar)
        view_menu.addAction(toolbar_action)

        statusbar_action = QAction("状态栏", self)
        statusbar_action.setCheckable(True)
        statusbar_action.setChecked(True)
        statusbar_action.triggered.connect(self.toggle_statusbar)
        view_menu.addAction(statusbar_action)

        # 工具菜单
        tools_menu = menubar.addMenu("工具")

        preferences_action = QAction(QIcon("ico/settings.png"), "首选项", self)
        tools_menu.addAction(preferences_action)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助")

        about_action = QAction(QIcon("ico/info.png"), "关于", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        docs_action = QAction(QIcon("ico/help.png"), "文档", self)
        docs_action.triggered.connect(self.open_documentation)
        help_menu.addAction(docs_action)

    def update_status_label(self, status):

        self.status_label.setText(status)

    def automatically_determine_the_analysis_type(self):
        """ 一键自动化 """

        self.status_label.setText("开始一键自动化...")
        file = self.Import_box.text()
        if not file:
            QMessageBox.warning(self, "警告", "请先选择流量文件!")
            return
        # 设置AI分析标志
        if self.ai_auto_analyze_check.isChecked():
            self.start_ai_analysis()
        else:
            if file.lower().endswith(('.log', '.txt')):
                self.analyze_logs(log_type='auto')
            elif file.lower().endswith(('.pcap', '.pcapng', '.cap')):
                self.start_analysis()

            else:
                QMessageBox.warning(self, "警告", "判断不出来文件类型")
                return

    def toggle_toolbar(self, visible):
        """切换工具栏显示"""
        self.toolbar.setVisible(visible)

    def toggle_statusbar(self, visible):
        """切换状态栏显示"""
        self.statusBar().setVisible(visible)

    # def create_tool_bar(self):
    #     """创建工具栏"""
    #     self.toolbar = QToolBar("主工具栏")
    #     self.toolbar.setIconSize(QSize(24, 24))
    #     self.toolbar.setStyleSheet("""
    #         QToolBar {
    #             background-color: qlineargradient(
    #                 spread:pad, x1:0, y1:0, x2:0, y2:1,
    #                 stop:0 #3A3A3A, stop:1 #2A2A2A
    #             );
    #             border-bottom: 1px solid #444;
    #             padding: 6px;
    #             spacing: 6px;
    #         }
    #
    #         QToolButton {
    #             padding: 6px;
    #             border-radius: 6px;
    #             background-color: transparent;
    #         }
    #
    #         QToolButton:hover {
    #             background-color: #505050;
    #         }
    #
    #         QToolButton:pressed {
    #             background-color: #2D2D2D;
    #         }
    #     """)
    #     self.addToolBar(self.toolbar)
    #
    #     # 添加工具栏按钮
    #     # new_btn = QToolButton()
    #     # new_btn.setIcon(QIcon("ico/new.png"))
    #     # new_btn.setToolTip("新建项目")
    #     # self.toolbar.addWidget(new_btn)
    #
    #     # open_btn = QToolButton()
    #     # open_btn.setIcon(QIcon("ico/open.png"))
    #     # open_btn.setToolTip("打开文件")
    #     # open_btn.clicked.connect(self.select_file)
    #     # self.toolbar.addWidget(open_btn)
    #     #
    #     # save_btn = QToolButton()
    #     # save_btn.setIcon(QIcon("ico/save.png"))
    #     # save_btn.setToolTip("保存")
    #     # self.toolbar.addWidget(save_btn)
    #
    #     # self.toolbar.addSeparator()
    #
    #     analyze_btn = QToolButton()
    #     analyze_btn.setIcon(QIcon("ico/analyze.png"))
    #     analyze_btn.setToolTip("开始分析")
    #     analyze_btn.clicked.connect(self.automatically_determine_the_analysis_type)
    #     self.toolbar.addWidget(analyze_btn)
    #
    #     stop_btn = QToolButton()
    #     stop_btn.setIcon(QIcon("ico/stop.png"))
    #     stop_btn.setToolTip("停止分析")
    #     stop_btn.clicked.connect(self.stop_analysis)
    #     stop_btn.setEnabled(False)
    #     self.toolbar.addWidget(stop_btn)
    #
    #     replay_btn = QToolButton()
    #     replay_btn.setIcon(QIcon("ico/replay.png"))
    #     replay_btn.setToolTip("重放请求")
    #     replay_btn.clicked.connect(self.replay_request)
    #     self.toolbar.addWidget(replay_btn)
    #
    #     self.toolbar.addSeparator()
    #
    #     export_btn = QToolButton()
    #     export_btn.setIcon(QIcon("ico/export.png"))
    #     export_btn.setToolTip("导出结果")
    #     export_btn.clicked.connect(self.export_results)
    #     self.toolbar.addWidget(export_btn)
    #
    #     # 导入框和浏览按钮打包为一组
    #     file_input_widget = QWidget()
    #     file_input_layout = QHBoxLayout(file_input_widget)
    #     file_input_layout.setContentsMargins(0, 0, 0, 0)
    #     file_input_layout.setSpacing(4)
    #
    #
    #     # 添加
    #     self.toolbar.addSeparator()
    #     self.Import_box = QLineEdit()
    #     self.Import_box.setPlaceholderText("CAP/PCAP/LOG/TXT文件...")
    #     self.Import_box.setReadOnly(True)
    #     self.Import_box.setMinimumWidth(200)
    #     self.Import_box.setStyleSheet("""
    #         QLineEdit {
    #             background-color: #252525;
    #             color: #EEE;
    #             border: 1px solid #444;
    #             border-radius: 4px;
    #             padding: 5px;
    #             font-family: Consolas, Courier New, monospace;
    #             font-size: 12px;
    #         }
    #     """)
    #     self.toolbar.addWidget(self.Import_box)
    #     self.Import_file_button = QPushButton("浏览...")
    #     self.Import_file_button.setStyleSheet("""
    #         QPushButton {
    #             background-color: #4A4A4A;
    #             color: white;
    #             border: none;
    #             border-radius: 4px;
    #             padding: 6px 12px;
    #             min-width: 70px;
    #         }
    #         QPushButton:hover {
    #             background-color: #5A5A5A;
    #         }
    #         QPushButton:pressed {
    #             background-color: #3A3A3A;
    #         }
    #     """)
    #     self.Import_file_button.clicked.connect(self.select_file)
    #     self.toolbar.addWidget(self.Import_file_button)

    def create_tool_bar(self):
        """创建工具栏"""
        self.toolbar = QToolBar("主工具栏")
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setStyleSheet("""
            QToolBar {
                background-color: qlineargradient(
                    spread:pad, x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3A3A3A, stop:1 #2A2A2A
                );
                border-bottom: 1px solid #444;
                padding: 6px;
                spacing: 6px;
            }

            QToolButton {
                padding: 6px;
                border-radius: 6px;
                background-color: transparent;
            }

            QToolButton:hover {
                background-color: #505050;
            }

            QToolButton:pressed {
                background-color: #2D2D2D;
            }
        """)
        self.addToolBar(self.toolbar)

        # 开始分析按钮
        analyze_btn = QToolButton()
        analyze_btn.setIcon(QIcon("ico/analyze.png"))
        analyze_btn.setToolTip("开始分析")
        analyze_btn.clicked.connect(self.automatically_determine_the_analysis_type)
        self.toolbar.addWidget(analyze_btn)

        # 停止分析按钮
        stop_btn = QToolButton()
        stop_btn.setIcon(QIcon("ico/stop.png"))
        stop_btn.setToolTip("停止分析")
        stop_btn.clicked.connect(self.stop_analysis)
        stop_btn.setEnabled(False)
        self.toolbar.addWidget(stop_btn)

        # 重放请求按钮
        replay_btn = QToolButton()
        replay_btn.setIcon(QIcon("ico/replay.png"))
        replay_btn.setToolTip("重放请求")
        replay_btn.clicked.connect(self.replay_request)
        self.toolbar.addWidget(replay_btn)

        self.toolbar.addSeparator()

        # 导出结果按钮
        export_btn = QToolButton()
        export_btn.setIcon(QIcon("ico/export.png"))
        export_btn.setToolTip("导出结果")
        export_btn.clicked.connect(self.export_results)
        self.toolbar.addWidget(export_btn)

        # 添加分隔符
        self.toolbar.addSeparator()

        # 导入框和浏览按钮打包为一组
        file_input_widget = QWidget()
        file_input_layout = QHBoxLayout(file_input_widget)
        file_input_layout.setContentsMargins(0, 0, 0, 0)
        file_input_layout.setSpacing(4)

        self.Import_box = QLineEdit()
        self.Import_box.setPlaceholderText("CAP/PCAP/LOG/TXT文件...")
        self.Import_box.setReadOnly(True)
        self.Import_box.setMinimumWidth(200)
        self.Import_box.setStyleSheet("""
            QLineEdit {
                background-color: #252525;
                color: #EEE;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 5px;
                font-family: Consolas, Courier New, monospace;
                font-size: 12px;
            }
        """)

        self.Import_file_button = QPushButton("浏览...")
        self.Import_file_button.setStyleSheet("""
            QPushButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                min-width: 70px;
            }
            QPushButton:hover {
                background-color: #5A5A5A;
            }
            QPushButton:pressed {
                background-color: #3A3A3A;
            }
        """)
        self.Import_file_button.clicked.connect(self.select_file)

        file_input_layout.addWidget(self.Import_box)
        file_input_layout.addWidget(self.Import_file_button)

        self.toolbar.addWidget(file_input_widget)

    def create_main_content(self):
        """创建主内容区域"""
        self.main_content = QWidget()
        main_layout = QHBoxLayout(self.main_content)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 创建侧边栏
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(150)  # 稍微加宽一点

        self.sidebar.setStyleSheet("""
            /* 设置 QListWidget 的背景色和字体 */
            QListWidget {
                background-color: #2B2B2B;  /* 背景色 */
                border: none;      
                font-size: 15px;            /* 字体大小 */
                color: #B1B1B1;             /* 字体颜色 */
                outline: none;              /* 去除焦点框 */
                padding: 10px 0;            /* 上下内边距 */
            }

            /* 设置每个列表项的样式 */
            QListWidget::item {
                height: 45px;              /* 高度 */
                padding: 8px 12px;         /* 内边距 */
                margin: 6px 10px;          /* 外边距 */
                border-radius: 10px;       /* 圆角 */

                border: none;              /* 无边框 */
            }

            /* 设置鼠标悬停时列表项的样式 */
            QListWidget::item:hover {
                background-color: rgba(70, 70, 70, 0.8);  /* 悬停时背景色 */
                color: #E0E0E0;                           /* 悬停时字体颜色 */
            }

            /* 设置选中时列表项的样式 */
            QListWidget::item:selected {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #E0F7FF, stop:1 #A0DFFF
                );
                color: black;                 /* 字体颜色调浅色背景下更易读 */
                font-weight: bold;

            }
        """)
        # # 添加侧边栏项目
        sidebar_items = [
            {"icon": "ico/dashboard.png", "text": "仪表盘", "tab": "dashboard"},
            {"icon": "ico/analysis.png", "text": "流量分析", "tab": "analysis"},
            {"icon": "ico/stats.png", "text": "统计分析", "tab": "stats"},
            {"icon": "ico/replay.png", "text": "请求重放", "tab": "replay"},
            {"icon": "ico/extract.png", "text": "文件提取", "tab": "extract"},
            {"icon": "ico/logs.png", "text": "Log分析", "tab": "log"},
            {"icon": "ico/intelligence.png", "text": "情报分析", "tab": "intelligence"},
            {"icon": "ico/ai.png", "text": "AI分析", "tab": "ai"},
            {"icon": "ico/report.png", "text": "报告生成", "tab": "report"},
            {"icon": "ico/settings.png", "text": "设置", "tab": "settings"}
        ]
        # 添加侧边栏项目
        # sidebar_items = [
        #     {"icon": "ico/dashboard.png", "text": "", "tab": "dashboard"},
        #     {"icon": "ico/analysis.png", "text": "", "tab": "analysis"},
        #     {"icon": "ico/stats.png", "text": "", "tab": "stats"},
        #     {"icon": "ico/replay.png", "text": "", "tab": "replay"},
        #     {"icon": "ico/extract.png", "text": "", "tab": "extract"},
        #     {"icon": "ico/logs.png", "text": "", "tab": "log"},
        #     {"icon": "ico/intelligence.png", "text": "", "tab": "intelligence"},
        #     {"icon": "ico/ai.png", "text": "", "tab": "ai"},
        #     {"icon": "ico/report.png", "text": "", "tab": "report"},
        #     {"icon": "ico/settings.png", "text": "", "tab": "settings"}
        # ]

        # for item in sidebar_items:
        #     list_item = QListWidgetItem(QIcon(item["icon"]), "")
        #     list_item.setData(Qt.ItemDataRole.UserRole, item["tab"])
        #     list_item.setToolTip(item["text"])  # 悬浮提示
        #     list_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        #     list_item.setForeground(QColor("#B1B1B1"))
        #     list_item.setSizeHint(QSize(70, 50))
        #     self.sidebar.addItem(list_item)

        for item in sidebar_items:
            list_item = QListWidgetItem(QIcon(item["icon"]), item["text"])
            list_item.setData(Qt.ItemDataRole.UserRole, item["tab"])
            list_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            list_item.setForeground(QColor("#B1B1B1"))  # 设置每个item的字体颜色
            list_item.setSizeHint(QSize(70, 50))  # 设置固定高度
            # list_item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            self.sidebar.addItem(list_item)
        # 默认选择仪表盘项
        self.sidebar.setCurrentRow(0)  # 设置为第一个项（仪表盘）
        self.sidebar.itemClicked.connect(self.switch_tab)
        main_layout.addWidget(self.sidebar)

        # 创建主工作区
        self.workspace = QTabWidget()
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 0)
        shadow.setColor(QColor(0, 0, 0, 130))
        self.workspace.setGraphicsEffect(shadow)
        self.workspace.setTabsClosable(True)
        self.workspace.tabCloseRequested.connect(self.close_tab)
        self.workspace.tabBar().hide()

        self.workspace.setStyleSheet("""
            /* 设置 QTabWidget 的背景色、圆角和内边距 */
            QTabWidget {
                background-color: #1E1E1E;     /* 背景色 */
                border-radius: 16px;            /* 圆角 */
                padding: 10px;                  /* 内边距 */
            }

            /* 设置 QTabWidget::pane 的样式，控制标签区域 */
            QTabWidget::pane {
                border: 1px solid #3A3A3A;     /* 边框 */
                border-radius: 16px;           /* 圆角 */
                margin: 8px;                   /* 外边距 */
                background-color: #252525;     /* 背景色 */
            }

            /* 设置 QTabBar 上关闭按钮的样式 */
            QTabBar::close-button {
                image: url(ico/close.png);      /* 关闭按钮图标 */
                subcontrol-position: right;    /* 关闭按钮的位置 */
                margin-left: 4px;              /* 左侧边距 */
            }

            /* 设置 QTabBar 上关闭按钮在鼠标悬停时的样式 */
            QTabBar::close-button:hover {
                background-color: #E81123;     /* 悬停时背景色 */
                border-radius: 4px;            /* 圆角 */
            }
        """)

        # 添加各个功能标签页
        self.tabs = {}
        self.create_dashboard_tab()
        self.create_intelligence_tab()
        self.create_ai_tab()
        self.create_analysis_tab()
        self.create_stats_tab()
        self.create_replay_tab()
        self.create_extract_tab()
        self.create_log_tab()

        main_layout.addWidget(self.workspace, stretch=1)

    def add_shadow_effects(self):
        """为关键组件添加阴影效果"""
        # 为侧边栏添加阴影
        sidebar_shadow = QGraphicsDropShadowEffect()
        sidebar_shadow.setBlurRadius(15)
        sidebar_shadow.setXOffset(5)
        sidebar_shadow.setYOffset(0)
        sidebar_shadow.setColor(QColor(0, 0, 0, 150))
        self.sidebar.setGraphicsEffect(sidebar_shadow)

        # 为工作区添加阴影
        workspace_shadow = QGraphicsDropShadowEffect()
        workspace_shadow.setBlurRadius(20)
        workspace_shadow.setXOffset(0)
        workspace_shadow.setYOffset(0)
        workspace_shadow.setColor(QColor(0, 0, 0, 100))
        self.workspace.setGraphicsEffect(workspace_shadow)

        # 为仪表盘卡片添加阴影
        for card in self.stats_cards.values():
            card_shadow = QGraphicsDropShadowEffect()
            card_shadow.setBlurRadius(10)
            card_shadow.setXOffset(3)
            card_shadow.setYOffset(3)
            card_shadow.setColor(QColor(0, 0, 0, 80))
            card['widget'].setGraphicsEffect(card_shadow)
    def switch_tab(self, item):
        """切换标签页"""
        tab_name = item.data(Qt.ItemDataRole.UserRole)
        if tab_name in self.tabs:
            self.workspace.setCurrentWidget(self.tabs[tab_name])

    def close_tab(self, index):
        """关闭标签页"""
        widget = self.workspace.widget(index)
        tab_name = None
        for name, w in self.tabs.items():
            if w == widget:
                tab_name = name
                break

        if tab_name and tab_name not in ["dashboard", "analysis", "stats", "replay", "log"]:
            self.workspace.removeTab(index)
            del self.tabs[tab_name]

    def create_intelligence_tab(self):
        """ 情报分析 """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 添加提示标签
        label = QLabel("该功能正在研发中，敬请期待！")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                color: #555555;
            }
        """)
        layout.addWidget(label)

        tab.setLayout(layout)

        # 加入到 tabs 和 workspace 中
        self.tabs["intelligence"] = tab
        self.workspace.addTab(tab, "情报分析")

    def create_ai_tab(self):
        """创建AI分析标签页"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/ai.png"), "AI分析")
        self.tabs["ai"] = tab

        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)  # 添加内边距，确保内容不贴边

        # 模型选择区域
        model_group = QGroupBox("AI模型选择")
        model_group.setStyleSheet(
            "QGroupBox { background-color: #2E2E2E; color: white; border-radius: 5px; padding: 10px; }")
        model_layout = QHBoxLayout(model_group)

        self.ai_model_combo = QComboBox()
        self.ai_model_combo.addItems(["本地模型 (Ollama)", "其他开发中"])
        self.ai_model_combo.setStyleSheet("color: white; background-color: #3A3A3A;")

        # self.ai_model_combo.addItems(["本地模型 (Ollama)", "DeepSeek", "OpenAI", "Gemini"])
        self.ai_model_combo.setCurrentIndex(0)

        model_layout.addWidget(QLabel("选择模型:"))
        model_layout.addWidget(self.ai_model_combo)
        model_layout.addStretch()

        # 自动分析开关
        self.ai_auto_analyze_check = QCheckBox("自动分析 (流量分析完成后自动调用AI分析)")
        self.ai_auto_analyze_check.setStyleSheet("""
            QCheckBox::indicator {
                border: 2px solid #007BFF;
                border-radius: 3px;
                background-color: #333333;
            }
            QCheckBox::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
            QCheckBox::indicator:checked::after {

                color: white;
                font-size: 14px;
                padding-left: 2px;
                padding-top: 2px;
            }
        """)
        #self.ai_auto_analyze_check.setChecked(True)

        # 分析控制区域
        control_group = QGroupBox("分析控制")
        control_group.setStyleSheet(
            "QGroupBox { background-color: #2E2E2E; color: white; border-radius: 5px; padding: 10px; }")
        control_layout = QVBoxLayout(control_group)

        self.ai_analyze_btn = QPushButton("开始AI分析")
        self.ai_analyze_btn.setIcon(QIcon("ico/ai.png"))

        self.ai_analyze_btn.clicked.connect(self.start_ai_analysis)

        self.ai_stop_btn = QPushButton("停止分析")
        self.ai_stop_btn.setIcon(QIcon("ico/stop.png"))
        self.ai_stop_btn.setEnabled(False)
        self.ai_stop_btn.clicked.connect(self.stop_ai_analysis)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.ai_analyze_btn)
        btn_layout.addWidget(self.ai_stop_btn)

        control_layout.addWidget(self.ai_auto_analyze_check)
        control_layout.addLayout(btn_layout)

        # 分析选项
        options_layout = QHBoxLayout()

        self.ai_analyze_urls = QCheckBox("分析URI请求")
        self.ai_analyze_urls.setChecked(True)
        self.ai_analyze_urls.setStyleSheet("""
            QCheckBox::indicator {
                border: 2px solid #007BFF;
                border-radius: 3px;
                background-color: #333333;
            }
            QCheckBox::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
            QCheckBox::indicator:checked::after {
                color: white;
                font-size: 14px;
                padding-left: 2px;
                padding-top: 2px;
            }
        """)

        self.ai_analyze_params = QCheckBox("分析请求参数（开发中）")
        self.ai_analyze_params.setChecked(False)
        self.ai_analyze_params.setStyleSheet("""
            QCheckBox::indicator {
                border: 2px solid #007BFF;
                border-radius: 3px;
                background-color: #333333;
            }
            QCheckBox::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
            QCheckBox::indicator:checked::after {
                color: white;
                font-size: 14px;
                padding-left: 2px;
                padding-top: 2px;
            }
        """)

        self.ai_analyze_headers = QCheckBox("分析请求头")
        self.ai_analyze_headers.setChecked(False)
        self.ai_analyze_headers.setStyleSheet("""
            QCheckBox::indicator {
                border: 2px solid #007BFF;
                border-radius: 3px;
                background-color: #333333;
            }
            QCheckBox::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
            QCheckBox::indicator:checked::after {
                color: white;
                font-size: 14px;
                padding-left: 2px;
                padding-top: 2px;
            }
        """)
        self.ai_request_Body = QCheckBox("分析请求体")
        self.ai_request_Body.setChecked(False)
        self.ai_request_Body.setStyleSheet("""
            QCheckBox::indicator {
                border: 2px solid #007BFF;
                border-radius: 3px;
                background-color: #333333;
            }
            QCheckBox::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
            QCheckBox::indicator:checked::after {
                color: white;
                font-size: 14px;
                padding-left: 2px;
                padding-top: 2px;
            }
        """)
        options_layout.addWidget(self.ai_analyze_urls)
        options_layout.addWidget(self.ai_analyze_params)
        options_layout.addWidget(self.ai_analyze_headers)
        options_layout.addWidget(self.ai_request_Body)
        options_layout.addStretch()

        control_layout.addLayout(options_layout)

        # 结果显示区域
        result_group = QGroupBox("AI分析结果")
        result_group.setStyleSheet(
            "QGroupBox { background-color: #2E2E2E; color: white; border-radius: 5px; padding: 10px; }")
        result_layout = QVBoxLayout(result_group)

        self.ai_result_text = QTextEdit()
        self.ai_result_text.setReadOnly(True)
        self.ai_result_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas, Courier New, monospace;
            }
        """)

        result_layout.addWidget(self.ai_result_text)

        # 新的分析的内容区域
        analysis_group = QGroupBox("分析的内容")
        analysis_group.setStyleSheet(
            "QGroupBox { background-color: #2E2E2E; color: white; border-radius: 5px; padding: 10px; }")
        analysis_layout = QVBoxLayout(analysis_group)

        self.ai_analysis_result_text = QTextEdit()
        self.ai_analysis_result_text.setReadOnly(True)
        self.ai_analysis_result_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas, Courier New, monospace;
            }
        """)

        analysis_layout.addWidget(self.ai_analysis_result_text)

        # 使用QHBoxLayout将 "AI分析结果" 和 "分析的内容" 放在一起
        result_h_layout = QHBoxLayout()
        result_h_layout.addWidget(result_group, stretch=1)
        result_h_layout.addWidget(analysis_group, stretch=1)

        # 将其添加到主布局
        layout.addWidget(model_group)
        layout.addWidget(control_group)
        layout.addLayout(result_h_layout)

        # 初始化AI分析线程
        self.ai_analysis_thread = None

        # self.ai_tab = AIAnalysisTab(self)
        # self.workspace.addTab(self.ai_tab, QIcon("ico/ai.png"), "AI分析")
        # self.tabs["ai"] = self.ai_tab

    def start_ai_analysis(self):
        ai_analysis_storing_data = defaultdict(lambda: {})
        ai_analysis_storing_data["request"] = {}

        # 通过字典存储复选框的状态
        self.analysis_selection = {
            "choose_url": self.ai_analyze_urls.isChecked(),
            "choose_params": self.ai_analyze_params.isChecked(),
            "choose_headers": self.ai_analyze_headers.isChecked(),
            "choose_Body": self.ai_request_Body.isChecked()
        }
        # 判断必须选择一个的条件
        if sum(self.analysis_selection.values()) == 0:
            QMessageBox.warning(self, "警告", "至少选择一个!")
            return

        # """开始AI分析"""
        # self.run_ai= True # 启动ai分析
        file = self.Import_box.text()

        if not file:
            QMessageBox.warning(self, "警告", "请先选择流量文件!")
            return

        # 先执行流量分析
        self.ai_result_text.clear()
        self.ai_analyze_btn.setEnabled(False)
        self.ai_stop_btn.setEnabled(True)

        if file.lower().endswith(('.log', '.txt')):
            self.analyze_logs(log_type='auto', ai_analysis_starts=ai_analysis_storing_data)
        elif file.lower().endswith(('.pcap', '.pcapng', '.cap')):
            self.start_analysis(ai_analysis_starts=ai_analysis_storing_data)

        # else:
        #     QMessageBox.warning(self, "警告", "判断不出来文件类型")
        #     return
        #
        #
        # self.ai_result_text.clear()
        # self.ai_analyze_btn.setEnabled(False)
        # self.ai_stop_btn.setEnabled(True)

    def create_dashboard_tab(self):
        """创建仪表盘标签页"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/dashboard.png"), "仪表盘")
        self.tabs["dashboard"] = tab

        layout = QVBoxLayout(tab)

        # 欢迎面板
        welcome_panel = QGroupBox("欢迎使用 TrafficEye")
        welcome_panel.setStyleSheet("""
            QGroupBox {
                border: 1px solid #444;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: #3A3A3A;
            }
            QGroupBox::title {
                color: #AAAAAA;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        # welcome_panel.setStyleSheet("""
        #     QGroupBox {
        #         border: 1px solid #2D2D2D;
        #         border-radius: 8px;
        #         margin-top: 10px;
        #         padding-top: 15px;
        #         font-weight: bold;
        #         background-color: #252525;
        #     }
        #     QGroupBox::title {
        #         color: #AAAAAA;
        #         subcontrol-origin: margin;
        #         left: 10px;
        #         padding: 0 5px;
        #     }
        # """)
        welcome_layout = QVBoxLayout(welcome_panel)

        # welcome_label = QLabel(f"""
        #     <h1 style="color:#4CAF50;">TrafficEye Web 研发版</h1>
        #     <p style="font-size:14px;">网络流量分析工具</p>
        #     <p>版本: {version} | 最后更新: {last_updated} | 作者：W啥都学</p>
        # """)
        welcome_label = QLabel(f"""
            <div style="text-align: center; font-family: 'Segoe UI', sans-serif;">
                <h1 style="
                    font-size: 30px;
                    color: #A0DFFF;
                    text-shadow: 0 0 6px #A0DFFF, 0 0 12px #E0F7FF;
                    margin: 0;
                ">
                    TrafficEye Web 研发版
                </h1>
                <p style="margin: 6px 0 2px; font-size: 16px; color: #BBBBBB;">网络流量分析工具</p>
                <p style="margin: 0; font-size: 13px; color: #999999;">
                    版本: {version} | 最后更新: {last_updated}
                </p>
            </div>
        """)

        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_layout.addWidget(welcome_label)

        # 快速操作按钮区域
        quick_actions = QWidget()
        quick_layout = QHBoxLayout(quick_actions)
        quick_layout.setContentsMargins(0, 0, 0, 0)
        quick_layout.setSpacing(10)  # 按钮间距

        # 按钮样式统一美化
        button_style = """
        QPushButton {
            border-radius: 10px;
            padding: 10px 12px;
            color: #eeeeee;
            
        }
        QPushButton:hover {
            background-color: #3c3f41;
            border: 1px solid #5dade2;
        }
        QPushButton:pressed {
            background-color: #2e6da4;
            border: 1px solid #2e6da4;
        }
        """

        btn_style = """
            QPushButton {
                padding: 12px 24px;
                border-radius: 6px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                min-width: 120px;

            }
            QPushButton:hover {
                opacity: 0.9;
            }
        """

        btn_analyze = QPushButton(QIcon("ico/analyze.png"), "一键识别自动化分析")
        btn_analyze.clicked.connect(self.automatically_determine_the_analysis_type)
        btn_analyze.setStyleSheet(button_style)
        # 设置图标大小，单位为像素
        btn_analyze.setIconSize(QSize(24, 24))  # 将图标的大小设置为 24x24 像素
        # 设置字体大小
        btn_analyze.setStyleSheet(btn_style + """
            background-color: #4CAF50;
            color: white;
            
        """)

        btn_replay = QPushButton(QIcon("ico/replay.png"), "请求重放")
        btn_replay.clicked.connect(lambda: self.workspace.setCurrentWidget(self.tabs["replay"]))
        btn_replay.setStyleSheet(button_style)
        # 设置图标大小，单位为像素
        btn_replay.setIconSize(QSize(24, 24))  # 将图标的大小设置为 24x24 像素
        # 设置字体大小
        btn_replay.setStyleSheet(btn_style + """
            background-color: #2196F3;
            color: white;
        """)

        btn_stats = QPushButton(QIcon("ico/stats.png"), "查看统计")
        btn_stats.clicked.connect(lambda: self.workspace.setCurrentWidget(self.tabs["stats"]))
        btn_stats.setStyleSheet(button_style)
        # 设置图标大小，单位为像素
        btn_stats.setIconSize(QSize(24, 24))  # 将图标的大小设置为 24x24 像素
        # 设置字体大小
        btn_stats.setStyleSheet(btn_style + """
            background-color: #FF9800;
            color: white;
        """)
        # 添加按钮
        quick_layout.addWidget(btn_analyze)
        quick_layout.addWidget(btn_replay)
        quick_layout.addWidget(btn_stats)



        welcome_layout.addWidget(quick_actions)
        layout.addWidget(welcome_panel)

        # 统计概览
        stats_panel = QGroupBox("统计概览")
        stats_panel.setStyleSheet("""
            QGroupBox {
                border: 1px solid #444;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: #3A3A3A;
            }
            QGroupBox::title {
                color: #AAAAAA;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        stats_layout = QHBoxLayout(stats_panel)
        stats_layout.setContentsMargins(15, 15, 15, 15)
        stats_layout.setSpacing(15)

        # 添加统计卡片
        self.stats_cards = {
            "total": {"widget": QWidget(), "value": QLabel("0")},
            "unique_url": {"widget": QWidget(), "value": QLabel("0")},
            "source_ip": {"widget": QWidget(), "value": QLabel("0")},
            "status_code": {"widget": QWidget(), "value": QLabel("0")},
            "danger": {"widget": QWidget(), "value": QLabel("0")}
        }

        # cards = [
        #     {"key": "total", "icon": "ico/traffic.png", "title": "总请求数", "color": "#2196F3"},
        #     {"key": "unique_url", "icon": "ico/url.png", "title": "唯一URL", "color": "#00BCD4"},
        #     {"key": "source_ip", "icon": "ico/ip.png", "title": "来源IP", "color": "#FF9800"},
        #     {"key": "status_code", "icon": "ico/status.png", "title": "状态码", "color": "#4CAF50"},
        #     {"key": "danger", "icon": "ico/danger.png", "title": "攻击危险", "color": "#F44336"}
        # ]

        cards = [
            {"key": "total", "icon": "ico/traffic.png", "title": "总请求数", "color": "#2196F3"},
            {"key": "unique_url", "icon": "ico/url.png", "title": "唯一URL", "color": "#00BCD4"},
            {"key": "source_ip", "icon": "ico/ip.png", "title": "来源IP", "color": "#FF9800"},
            {"key": "status_code", "icon": "ico/status.png", "title": "状态码", "color": "#4CAF50"},
            {"key": "danger", "icon": "ico/danger.png", "title": "攻击危险", "color": "#F44336"}
        ]

        for card in cards:
            card_data = self.stats_cards[card["key"]]
            card_widget = card_data["widget"]
            card_widget.setStyleSheet(f"""
                background-color: #2D2D2D;

            """)
            card_layout = QVBoxLayout(card_widget)
            card_layout.setContentsMargins(15, 15, 15, 15)
            card_layout.setSpacing(10)

            # 图标和标题
            top_widget = QWidget()
            top_layout = QHBoxLayout(top_widget)
            top_layout.setContentsMargins(0, 0, 0, 0)

            icon = QLabel()
            icon.setPixmap(QIcon(card["icon"]).pixmap(24, 24))

            title = QLabel(card["title"])
            title.setStyleSheet(f"color: {card['color']}; font-weight: bold; font-size: 14px;")

            top_layout.addWidget(icon)
            top_layout.addWidget(title)
            top_layout.addStretch()

            # 数值
            value = card_data["value"]
            value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            value.setStyleSheet("""
                font-size: 28px;
                font-weight: bold;
                color: #FFFFFF;
            """)

            card_layout.addWidget(top_widget)
            card_layout.addWidget(value)
            stats_layout.addWidget(card_widget)

        layout.addWidget(stats_panel)

        # 最近活动
        recent_panel = QGroupBox("最近操作")
        recent_panel.setStyleSheet("""
            QGroupBox {
                border: 1px solid #444;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: #3A3A3A;
            }
            QGroupBox::title {
                color: #AAAAAA;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        recent_layout = QVBoxLayout(recent_panel)
        recent_layout.setContentsMargins(0, 15, 0, 0)

        self.recent_table = QTableWidget()
        self.recent_table.setColumnCount(4)
        self.recent_table.setShowGrid(False)
        self.recent_table.setHorizontalHeaderLabels(["时间", "操作", "文件", "状态"])
        self.recent_table.horizontalHeader().setStretchLastSection(True)
        self.recent_table.verticalHeader().setVisible(False)
        self.recent_table.setStyleSheet("""
                    QTableWidget::item:hover {
                background-color: #444444;
            }
            QTableWidget {
                border: none;
                background-color: #252525;
                alternate-background-color: #2D2D2D;
                selection-background-color: #3A3A3A;
                color: #DDDDDD;
            }
            QHeaderView::section {
                background-color: #2D2D2D;
                padding: 10px;
                border: none;
                font-weight: bold;
                color: #AAAAAA;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #3A3A3A;
            }
            QTableWidget::item:selected {
                background-color: #3A3A3A;
                color: white;
            }

            QScrollBar:vertical {
                background: #1e1e1e;
                width: 12px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #444;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                background: none;
                height: 0px;
            }
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical {
                background: none;
            }

            QScrollBar:horizontal {
                background: #1e1e1e;
                height: 12px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:horizontal {
                background: #444;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal {
                background: none;
                width: 0px;
            }
            QScrollBar::add-page:horizontal,
            QScrollBar::sub-page:horizontal {
                background: none;
            }
        """)

        # 设置表格列宽
        self.recent_table.setColumnWidth(0, 150)
        self.recent_table.setColumnWidth(1, 120)
        self.recent_table.setColumnWidth(2, 200)


        self.recent_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.recent_table.customContextMenuRequested.connect(self.show_recent_context_menu)


        recent_layout.addWidget(self.recent_table)
        layout.addWidget(recent_panel)

        # 加载最近活动
        self.load_recent_activity()

    # 在create_dashboard_tab方法中更新卡片样式
    # def create_dashboard_tab(self):
    #     """创建仪表盘标签页"""
    #     tab = QWidget()
    #     self.workspace.addTab(tab, QIcon("ico/dashboard.png"), "仪表盘")
    #     self.tabs["dashboard"] = tab
    #
    #     layout = QVBoxLayout(tab)
    #     layout.setContentsMargins(15, 15, 15, 15)
    #     layout.setSpacing(15)
    #
    #     # 欢迎面板
    #     welcome_panel = QWidget()
    #     welcome_panel.setObjectName("welcomePanel")
    #     welcome_panel.setStyleSheet("""
    #         #welcomePanel {
    #             background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
    #                 stop:0 #1E3B70, stop:1 #2A5298);
    #             border-radius: 8px;
    #             padding: 20px;
    #         }
    #     """)
    #     welcome_layout = QVBoxLayout(welcome_panel)
    #
    #     # 添加应用图标和标题
    #     logo_title_layout = QHBoxLayout()
    #     logo_label = QLabel()
    #     logo_pixmap = QPixmap("ico/l.png").scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio,
    #                                               Qt.TransformationMode.SmoothTransformation)
    #     logo_label.setPixmap(logo_pixmap)
    #     logo_title_layout.addWidget(logo_label)
    #
    #     title_layout = QVBoxLayout()
    #     title_label = QLabel("TrafficEye Web")
    #     title_label.setStyleSheet("""
    #         font-size: 24px;
    #         font-weight: bold;
    #         color: white;
    #     """)
    #     subtitle_label = QLabel("网络流量分析工具")
    #     subtitle_label.setStyleSheet("""
    #         font-size: 14px;
    #         color: rgba(255, 255, 255, 0.8);
    #     """)
    #     title_layout.addWidget(title_label)
    #     title_layout.addWidget(subtitle_label)
    #     logo_title_layout.addLayout(title_layout)
    #     logo_title_layout.addStretch()
    #
    #     welcome_layout.addLayout(logo_title_layout)
    #
    #     # 版本信息
    #     version_layout = QHBoxLayout()
    #     version_layout.addStretch()
    #     version_info = QLabel(f"版本: {version} | 最后更新: {last_updated} | 作者: {__author__}")
    #     version_info.setStyleSheet("font-size: 11px; color: rgba(255, 255, 255, 0.7);")
    #     version_layout.addWidget(version_info)
    #     welcome_layout.addLayout(version_layout)
    #
    #     # 快速操作按钮区域
    #     quick_actions = QWidget()
    #     quick_layout = QHBoxLayout(quick_actions)
    #     quick_layout.setContentsMargins(0, 15, 0, 0)
    #     quick_layout.setSpacing(15)
    #
    #     # 按钮样式
    #     btn_style = """
    #         QPushButton {
    #             padding: 10px 20px;
    #             border-radius: 6px;
    #             font-size: 14px;
    #             font-weight: bold;
    #             border: none;
    #             min-width: 120px;
    #         }
    #         QPushButton:hover {
    #             opacity: 0.9;
    #         }
    #     """
    #
    #     btn_analyze = QPushButton(QIcon("ico/analyze.png"), "一键自动化分析")
    #     btn_analyze.clicked.connect(self.automatically_determine_the_analysis_type)
    #     btn_analyze.setStyleSheet(btn_style + """
    #         background-color: #4CAF50;
    #         color: white;
    #     """)
    #
    #     btn_replay = QPushButton(QIcon("ico/replay.png"), "请求重放")
    #     btn_replay.clicked.connect(lambda: self.workspace.setCurrentWidget(self.tabs["replay"]))
    #     btn_replay.setStyleSheet(btn_style + """
    #         background-color: #2196F3;
    #         color: white;
    #     """)
    #
    #     btn_stats = QPushButton(QIcon("ico/stats.png"), "统计分析")
    #     btn_stats.clicked.connect(lambda: self.workspace.setCurrentWidget(self.tabs["stats"]))
    #     btn_stats.setStyleSheet(btn_style + """
    #         background-color: #FF9800;
    #         color: white;
    #     """)
    #
    #     quick_layout.addWidget(btn_analyze)
    #     quick_layout.addWidget(btn_replay)
    #     quick_layout.addWidget(btn_stats)
    #     welcome_layout.addWidget(quick_actions)
    #     layout.addWidget(welcome_panel)
    #
    #     # 统计概览
    #     stats_panel = QGroupBox("统计概览")
    #     stats_panel.setStyleSheet("""
    #         QGroupBox {
    #             border: 1px solid #444;
    #             border-radius: 8px;
    #             margin-top: 10px;
    #             padding-top: 25px;
    #             background: #3A3A3A;
    #         }
    #         QGroupBox::title {
    #             color: #AAAAAA;
    #             subcontrol-origin: margin;
    #             left: 15px;
    #             padding: 0 5px;
    #         }
    #     """)
    #     stats_layout = QHBoxLayout(stats_panel)
    #     stats_layout.setContentsMargins(15, 15, 15, 15)
    #     stats_layout.setSpacing(15)
    #
    #     # 添加统计卡片
    #     self.stats_cards = {
    #         "total": {"widget": QWidget(), "value": QLabel("0")},
    #         "unique_url": {"widget": QWidget(), "value": QLabel("0")},
    #         "source_ip": {"widget": QWidget(), "value": QLabel("0")},
    #         "status_code": {"widget": QWidget(), "value": QLabel("0")},
    #         "danger": {"widget": QWidget(), "value": QLabel("0")}
    #     }
    #
    #     cards = [
    #         {"key": "total", "icon": "ico/traffic.png", "title": "总请求数", "color": "#2196F3"},
    #         {"key": "unique_url", "icon": "ico/url.png", "title": "唯一URL", "color": "#00BCD4"},
    #         {"key": "source_ip", "icon": "ico/ip.png", "title": "来源IP", "color": "#FF9800"},
    #         {"key": "status_code", "icon": "ico/status.png", "title": "状态码", "color": "#4CAF50"},
    #         {"key": "danger", "icon": "ico/danger.png", "title": "攻击危险", "color": "#F44336"}
    #     ]
    #
    #     for card in cards:
    #         card_data = self.stats_cards[card["key"]]
    #         card_widget = card_data["widget"]
    #         card_widget.setStyleSheet(f"""
    #             background-color: #252525;
    #             border-radius: 6px;
    #             padding: 15px;
    #         """)
    #         card_layout = QVBoxLayout(card_widget)
    #         card_layout.setContentsMargins(5, 5, 5, 5)
    #         card_layout.setSpacing(10)
    #
    #         # 图标和标题
    #         top_widget = QWidget()
    #         top_layout = QHBoxLayout(top_widget)
    #         top_layout.setContentsMargins(0, 0, 0, 0)
    #
    #         icon = QLabel()
    #         icon.setPixmap(QIcon(card["icon"]).pixmap(24, 24))
    #
    #         title = QLabel(card["title"])
    #         title.setStyleSheet(f"""
    #             color: {card['color']};
    #             font-weight: bold;
    #             font-size: 14px;
    #         """)
    #
    #         top_layout.addWidget(icon)
    #         top_layout.addWidget(title)
    #         top_layout.addStretch()
    #
    #         # 数值
    #         value = card_data["value"]
    #         value.setAlignment(Qt.AlignmentFlag.AlignCenter)
    #         value.setStyleSheet("""
    #             font-size: 28px;
    #             font-weight: bold;
    #             color: #FFFFFF;
    #         """)
    #
    #         card_layout.addWidget(top_widget)
    #         card_layout.addWidget(value)
    #         stats_layout.addWidget(card_widget)
    #
    #     layout.addWidget(stats_panel)
    #
    #     # 最近活动
    #     recent_panel = QGroupBox("最近操作")
    #     recent_panel.setStyleSheet("""
    #         QGroupBox {
    #             border: 1px solid #444;
    #             border-radius: 8px;
    #             margin-top: 10px;
    #             padding-top: 25px;
    #             background: #3A3A3A;
    #         }
    #         QGroupBox::title {
    #             color: #AAAAAA;
    #             subcontrol-origin: margin;
    #             left: 15px;
    #             padding: 0 5px;
    #         }
    #     """)
    #     recent_layout = QVBoxLayout(recent_panel)
    #     recent_layout.setContentsMargins(0, 15, 0, 0)
    #
    #     self.recent_table = QTableWidget()
    #     self.recent_table.setColumnCount(4)
    #     self.recent_table.setShowGrid(False)
    #     self.recent_table.setHorizontalHeaderLabels(["时间", "操作", "文件", "状态"])
    #     self.recent_table.horizontalHeader().setStretchLastSection(True)
    #     self.recent_table.verticalHeader().setVisible(False)
    #     self.recent_table.setStyleSheet("""
    #         QTableWidget {
    #             border: none;
    #             background-color: #252525;
    #             alternate-background-color: #2D2D2D;
    #             selection-background-color: #3A3A3A;
    #             color: #DDDDDD;
    #         }
    #         QHeaderView::section {
    #             background-color: #2D2D2D;
    #             padding: 10px;
    #             border: none;
    #             font-weight: bold;
    #             color: #AAAAAA;
    #         }
    #         QTableWidget::item {
    #             padding: 8px;
    #             border-bottom: 1px solid #3A3A3A;
    #         }
    #         QTableWidget::item:selected {
    #             background-color: #3A3A3A;
    #             color: white;
    #         }
    #     """)
    #
    #     # 设置表格列宽
    #     self.recent_table.setColumnWidth(0, 150)
    #     self.recent_table.setColumnWidth(1, 120)
    #     self.recent_table.setColumnWidth(2, 200)
    #
    #     recent_layout.addWidget(self.recent_table)
    #     layout.addWidget(recent_panel)
    #
    #     # 加载最近活动
    #     self.load_recent_activity()
    def show_recent_context_menu(self, position):
        """ 删除该条记录或全部记录 """
        index = self.recent_table.indexAt(position)
        if not index.isValid():
            return

        menu = QMenu()

        # "删除该条记录" 操作
        delete_action = menu.addAction("删除该条记录")

        # "删除所有记录" 操作
        delete_all_action = menu.addAction("删除所有记录")

        # 右键菜单展示
        action = menu.exec(self.recent_table.viewport().mapToGlobal(position))

        if action == delete_action:
            row = index.row()

            # 删除表格中的该行
            self.recent_table.removeRow(row)

            # 删除数据源中的对应记录
            self.delete_recent_entry(row)

        elif action == delete_all_action:
            # 删除所有记录
            row_count = self.recent_table.rowCount()
            for row in range(row_count - 1, -1, -1):  # 从最后一行开始删除
                self.recent_table.removeRow(row)
                self.delete_recent_entry(row)

    def delete_recent_entry(self, row_index):
        """ 删除该条记录存储 """
        path = "history/trafficeye_data.json"
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        recent = data.get("recent", [])
        if 0 <= row_index < len(recent):
            del recent[row_index]
            data["recent"] = recent
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

    def update_dashboard_stats(self):
        """更新仪表盘统计信息"""
        if not hasattr(self, 'stats_cards'):
            return

        total_requests = sum(stats['count'] for stats in self.url_stats.values())
        try:
            danger = 0
            for i in self.url_stats.values():
                if not "未检测到安全威胁" in i['danger']:

                    if i['danger']:
                        print(i['danger'])
                        danger += 1
        except:
            danger = ""

        unique_urls = len(self.url_stats)
        source_ips = set()
        status_codes = set()

        for stats in self.url_stats.values():
            source_ips.update(stats['source_ips'].keys())
            status_codes.update(stats['status_codes'].keys())

        self.stats_cards["total"]["value"].setText(str(total_requests))
        self.stats_cards["unique_url"]["value"].setText(str(unique_urls))
        self.stats_cards["source_ip"]["value"].setText(str(len(source_ips)))
        self.stats_cards["status_code"]["value"].setText(str(len(status_codes)))
        self.stats_cards["danger"]["value"].setText(str(danger))

    def create_analysis_tab(self):
        """创建流量分析选项卡"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/analysis.png"), "流量分析")
        self.tabs["analysis"] = tab

        # 主布局使用水平分割器
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setHandleWidth(2)

        # 左侧：结果区域
        result_group = QGroupBox("分析结果")
        result_group.setStyleSheet("""
            QGroupBox {
                font: 12px 'Microsoft YaHei';
                border: 1px solid #444;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: #3A3A3A;
            }
            QGroupBox::title {
                color: #AAAAAA;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        result_layout = QVBoxLayout(result_group)
        result_layout.setContentsMargins(8, 15, 8, 8)


        # 结果文本框
        self.analysis_text_edit = QTextEdit()
        self.analysis_text_edit.setPlaceholderText("分析结果将显示在这里...")
        self.analysis_text_edit.setReadOnly(True)
        self.analysis_text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        font = self.analysis_text_edit.font()
        font.setFamily("Consolas")
        font.setPointSize(10)
        self.analysis_text_edit.setFont(font)

        self.analysis_text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
                border-radius: 3px;
                padding: 8px;
            }
        """)

        result_layout.addWidget(self.analysis_text_edit, stretch=1)
        # 创建状态标签：用于显示当前状态（例如 "就绪"、"分析中" 等）
        self.status_create_analysis_tab = QLabel()
        result_layout.addWidget(self.status_create_analysis_tab)
        main_splitter.addWidget(result_group)

        # 右侧：控制面板区域
        right_panel = QWidget()
        right_panel.setStyleSheet("background-color: #3A3A3A;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(5, 5, 5, 5)
        right_layout.setSpacing(10)

        # 上部：文件和控制区域
        control_group = QGroupBox("文件和控制")
        control_group.setStyleSheet("""
            QGroupBox {
                font: 12px 'Microsoft YaHei';
                border: 1px solid #444;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background: #3A3A3A;
            }
            QGroupBox::title {
                color: #AAAAAA;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        control_layout = QVBoxLayout(control_group)
        control_layout.setSpacing(10)
        control_layout.setContentsMargins(10, 15, 10, 10)

        # 分析方式选择
        method_group = QGroupBox("可选分析方式")
        method_group.setStyleSheet("""
            QGroupBox {
                font: 11px 'Microsoft YaHei';
                border: 1px solid #555;
                border-radius: 3px;
                margin-top: 10px;
                padding-top: 15px;
                background: #3A3A3A;
            }
            QGroupBox::title {
                color: #AAAAAA;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        method_layout = QHBoxLayout(method_group)
        method_layout.setContentsMargins(8, 15, 8, 8)

        self.flow_pyshark_radio = QRadioButton("使用pyshark (Python库)")

        self.flow_pyshark_radio.setStyleSheet("""
            QRadioButton::indicator {

                border: 2px solid #007BFF;
                border-radius: 8px;
                background-color: transparent;
            }
            QRadioButton::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
        """)
        self.tshark_radio = QRadioButton("使用tshark")
        self.tshark_radio.setChecked(True)
        self.tshark_radio.setStyleSheet("""
            QRadioButton::indicator {

                border: 2px solid #007BFF;
                border-radius: 8px;
                background-color: transparent;
            }
            QRadioButton::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
        """)

        method_layout.addWidget(self.flow_pyshark_radio)
        method_layout.addWidget(self.tshark_radio)

        control_layout.addWidget(method_group)

        # 按钮区域
        button_group = QGroupBox("操作")
        button_group.setStyleSheet(method_group.styleSheet())
        button_layout = QVBoxLayout(button_group)
        button_layout.setContentsMargins(8, 15, 8, 8)
        button_layout.setSpacing(8)

        # 第一行按钮
        top_button_layout = QHBoxLayout()
        top_button_layout.setSpacing(5)

        self.start_analysis_button = QPushButton("开始分析")
        self.start_analysis_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
                /* color: #4CAF50;  字体绿色 */
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        self.start_analysis_button.clicked.connect(self.start_analysis)
        self.start_analysis_button.setIcon(QIcon("ico/analyze.png"))
        top_button_layout.addWidget(self.start_analysis_button)

        self.stop_analysis_button = QPushButton("停止分析")
        self.stop_analysis_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
                /*color: #F44336;   红色字体 */
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)

        self.stop_analysis_button.clicked.connect(self.stop_analysis)
        self.stop_analysis_button.setIcon(QIcon("ico/stop.png"))
        self.stop_analysis_button.setEnabled(False)
        top_button_layout.addWidget(self.stop_analysis_button)
        button_layout.addLayout(top_button_layout)

        # 第二行按钮
        bottom_button_layout = QHBoxLayout()
        bottom_button_layout.setSpacing(5)

        self.clear_button = QPushButton("清除结果")
        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
                /*color: #FFEB3B;   黄色字体 */
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)

        self.clear_button.clicked.connect(self.clear_results)
        self.clear_button.setIcon(QIcon("ico/clear.png"))
        bottom_button_layout.addWidget(self.clear_button)

        self.export_button = QPushButton("导出结果")
        self.export_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
               /* color: #2196F3;   蓝色字体 */
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)

        self.export_button.clicked.connect(self.export_results)
        self.export_button.setIcon(QIcon("ico/export.png"))
        bottom_button_layout.addWidget(self.export_button)
        button_layout.addLayout(bottom_button_layout)

        control_layout.addWidget(button_group)

        # # 进度条
        # self.progress_bar = QProgressBar()
        # self.progress_bar.setRange(0, 100)
        # self.progress_bar.setValue(0)
        # self.progress_bar.setTextVisible(True)
        # self.progress_bar.setStyleSheet("""
        #     QProgressBar {
        #         border: 1px solid #555;
        #         border-radius: 3px;
        #         text-align: center;
        #         background: #3A3A3A;
        #     }
        #     QProgressBar::chunk {
        #         background-color: #4CAF50;
        #         width: 10px;
        #     }
        # """)
        # control_layout.addWidget(self.progress_bar)

        right_layout.addWidget(control_group)

        # 添加 SSL 密钥日志文件路径输入框
        ssl_keylog_group = QGroupBox("可选参数 SSL 密钥日志文件路径")
        ssl_keylog_group.setStyleSheet(method_group.styleSheet())
        ssl_keylog_layout = QHBoxLayout(ssl_keylog_group)
        ssl_keylog_layout.setContentsMargins(8, 15, 8, 8)

        self.ssl_keylog_input = QLineEdit()
        self.ssl_keylog_input.setPlaceholderText("请输入ssl keys日志文件路径")
        self.ssl_keylog_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #555;
                border-radius: 3px;
                padding: 5px;
                background: #3A3A3A;
            }
        """)
        ssl_keylog_layout.addWidget(self.ssl_keylog_input)
        right_layout.addWidget(ssl_keylog_group)

        # 搜索选项区域
        search_options_group = QGroupBox("可选参数 搜索选项")
        search_options_group.setStyleSheet(method_group.styleSheet())
        search_options_layout = QGridLayout(search_options_group)
        search_options_layout.setContentsMargins(8, 15, 8, 8)
        search_options_layout.setVerticalSpacing(5)
        search_options_layout.setHorizontalSpacing(10)

        # URI搜索
        self.uri_label = QLabel("URI 搜索:")
        self.uri_label.setStyleSheet("font-weight: bold;")
        self.uri_input = QLineEdit()
        self.uri_input.setPlaceholderText("例如: /api/v2/")
        self.uri_input.setStyleSheet(self.ssl_keylog_input.styleSheet())
        search_options_layout.addWidget(self.uri_label, 0, 0)
        search_options_layout.addWidget(self.uri_input, 1, 0)

        # 分隔线
        separator1 = QFrame()
        separator1.setFrameShape(QFrame.Shape.HLine)
        separator1.setFrameShadow(QFrame.Shadow.Sunken)
        separator1.setStyleSheet("color: #DDD;")
        search_options_layout.addWidget(separator1, 2, 0)

        # 关键字搜索
        self.search_label = QLabel("可选参数 键字搜索")
        self.search_label.setStyleSheet("font-weight: bold;")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("例如: User-Agent: Mozilla/5.0")
        self.search_input.setStyleSheet(self.ssl_keylog_input.styleSheet())
        search_options_layout.addWidget(self.search_label, 3, 0)
        search_options_layout.addWidget(self.search_input, 4, 0)

        # 显示选项区域
        display_options_group = QGroupBox("显示选项")
        display_options_group.setStyleSheet(method_group.styleSheet())
        display_options_layout = QVBoxLayout(display_options_group)
        display_options_layout.setContentsMargins(8, 15, 8, 8)
        display_options_layout.setSpacing(8)

        self.request_only_checkbox = QCheckBox("仅显示请求")
        self.response_only_checkbox = QCheckBox("仅显示响应")
        self.body_checkbox = QCheckBox("显示原始字节流")

        # 统一设置复选框样式
        checkbox_style = """
            QCheckBox {
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
        """
        for checkbox in [self.request_only_checkbox, self.response_only_checkbox, self.body_checkbox]:
            checkbox.setStyleSheet(checkbox_style)

        display_options_layout.addWidget(self.request_only_checkbox)
        display_options_layout.addWidget(self.response_only_checkbox)
        display_options_layout.addWidget(self.body_checkbox)

        right_layout.addWidget(search_options_group)
        right_layout.addWidget(display_options_group)

        # 添加伸缩项使内容顶部对齐
        right_layout.addStretch(1)

        main_splitter.addWidget(right_panel)

        # 设置分割器样式和比例
        main_splitter.setStyleSheet("""
            QSplitter::handle {
                background: #3E3E3E;
            }
        """)
        main_splitter.setSizes([1120, 280])

        # 将分割器设置为主布局
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(5, 5, 5, 5)
        tab_layout.addWidget(main_splitter)

    def create_settings_tab(self):
        """创建设置标签页"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/settings.png"), "设置")
        self.tabs["settings"] = tab

        layout = QVBoxLayout(tab)

        # 创建选项卡
        tab_widget = QTabWidget()
        # 设置选项卡的样式
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #5C5C5C; /* 边框颜色 */
                background-color: #383838;  /* 背景颜色 */
            }
            QTabBar::tab {
                background-color: #4A4A4A; /* 标签背景颜色 */
                color: white;               /* 标签文字颜色 */
                padding: 10px;
                border: 1px solid #5C5C5C;  /* 标签边框 */
                border-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #007ACC;  /* 选中的标签背景颜色 */
                color: white;               /* 选中标签的文字颜色 */
            }
            QTabBar::tab:hover {
                background-color: #3A3A3A;  /* 标签悬停时的背景颜色 */
            }
        """)
        # 1. 常规设置
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)

        # 应用信息
        app_info_group = QGroupBox("应用信息")
        app_info_layout = QFormLayout(app_info_group)

        self.app_name = QLabel("TrafficEye Web")
        self.app_version = QLabel(f"版本: {version}")
        self.app_author = QLabel("作者: W啥都学")
        self.last_update = QLabel(f"最后更新: {last_updated} ")

        app_info_layout.addRow("名称:", self.app_name)
        app_info_layout.addRow("版本:", self.app_version)
        app_info_layout.addRow("作者:", self.app_author)
        app_info_layout.addRow("最后更新:", self.last_update)

        general_layout.addWidget(app_info_group)

        # 更新检查
        # update_group = QGroupBox("更新检查")
        # update_layout = QVBoxLayout(update_group)
        #
        # self.auto_update_check = QCheckBox("自动检查更新")
        # self.auto_update_check.setChecked(True)

        # check_update_btn = QPushButton("立即检查更新")
        # check_update_btn.clicked.connect(self.check_for_updates)
        #
        # update_layout.addWidget(self.auto_update_check)
        # update_layout.addWidget(check_update_btn)

        # 2. 使用QHBoxLayout进行左右排列
        image_layout = QHBoxLayout()

        # 公众号二维码
        wechat_image_label = QLabel()
        pixmap = QPixmap("ico/qrcode_for_gh_e911bdfdbe01_344.png")  # 假设图片名为 wechat.png
        wechat_image_label.setPixmap(pixmap)
        wechat_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)  # 图片居中显示
        # wechat_image_label.setFixedSize(200, 200)  # 设置固定大小，保持二维码的统一

        # 支付二维码
        wechatzf_image_label = QLabel()
        pixmap_zf = QPixmap("ico/wxzf.jpg")  # 假设图片名为 wechat.png
        wechatzf_image_label.setPixmap(pixmap_zf)
        wechatzf_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)  # 图片居中显示
        # wechatzf_image_label.setFixedSize(200, 200)  # 设置固定大小，保持二维码的统一

        # 将图片添加到左右布局
        image_layout.addWidget(wechat_image_label)
        image_layout.addSpacing(20)  # 图片间隔
        image_layout.addWidget(wechatzf_image_label)
        # 将左右布局添加到常规设置的布局中
        general_layout.addLayout(image_layout)

        # general_layout.addWidget(update_group)

        # 2. 正则表达式配置
        regex_tab = QWidget()
        regex_layout = QVBoxLayout(regex_tab)

        # 正则表达式类别选择
        regex_category_group = QGroupBox("正则表达式类别")
        regex_category_layout = QHBoxLayout(regex_category_group)

        self.regex_category = QComboBox()
        self.regex_category.addItems(["日志格式识别", "日志解析", "安全检测"])
        self.regex_category.setStyleSheet("color: white; background-color: #3A3A3A;")
        self.regex_category.currentIndexChanged.connect(self.load_regex_config)

        regex_category_layout.addWidget(QLabel("选择类别:"))
        regex_category_layout.addWidget(self.regex_category, stretch=1)
        regex_layout.addWidget(regex_category_group)

        # 正则表达式编辑区域
        regex_edit_group = QGroupBox("正则表达式配置")
        regex_edit_layout = QVBoxLayout(regex_edit_group)

        # 规则名称选择
        self.rule_name_combo = QComboBox()
        self.rule_name_combo.currentIndexChanged.connect(self.load_selected_rule)
        self.rule_name_combo.setStyleSheet("color: white; background-color: #3A3A3A;")
        regex_edit_layout.addWidget(self.rule_name_combo)

        # 规则名称编辑
        self.rule_name_edit = QLineEdit()
        regex_edit_layout.addWidget(QLabel("规则名称:"))
        regex_edit_layout.addWidget(self.rule_name_edit)

        # 正则表达式编辑
        self.regex_edit = QTextEdit()
        self.regex_edit.setPlaceholderText("在此输入正则表达式...")
        self.regex_edit.setAcceptRichText(False)
        self.regex_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        # 添加语法高亮
        self.highlighter = RegexHighlighter(self.regex_edit.document())

        regex_edit_layout.addWidget(QLabel("正则表达式:"))
        regex_edit_layout.addWidget(self.regex_edit)

        # 测试区域
        test_group = QGroupBox("测试正则表达式")
        test_layout = QVBoxLayout(test_group)

        self.test_input = QTextEdit()
        self.test_input.setPlaceholderText("输入测试文本...")
        self.test_output = QTextEdit()
        self.test_output.setReadOnly(True)

        test_btn = QPushButton("测试正则表达式")
        test_btn.clicked.connect(self.test_regex)

        test_layout.addWidget(QLabel("测试输入:"))
        test_layout.addWidget(self.test_input)
        test_layout.addWidget(test_btn)
        test_layout.addWidget(QLabel("匹配结果:"))
        test_layout.addWidget(self.test_output)
        regex_edit_layout.addWidget(test_group)

        # 操作按钮
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("保存更改")
        save_btn.clicked.connect(self.save_regex_config)
        reset_btn = QPushButton("重置")
        reset_btn.clicked.connect(self.load_regex_config)
        add_btn = QPushButton("添加新规则")
        add_btn.clicked.connect(self.add_new_rule)
        delete_btn = QPushButton("删除规则")
        delete_btn.clicked.connect(self.delete_rule)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(reset_btn)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(delete_btn)
        regex_edit_layout.addLayout(btn_layout)

        regex_layout.addWidget(regex_edit_group)

        # 3. 代理设置
        proxy_tab = QWidget()
        proxy_layout = QVBoxLayout(proxy_tab)

        # proxy_group = QGroupBox("代理设置")
        # proxy_form = QFormLayout(proxy_group)
        #
        # self.http_proxy = QLineEdit()
        # self.http_proxy.setPlaceholderText("http://127.0.0.1:8080")
        # self.https_proxy = QLineEdit()
        # self.https_proxy.setPlaceholderText("http://127.0.0.1:8080")
        #
        # proxy_form.addRow("HTTP代理:", self.http_proxy)
        # proxy_form.addRow("HTTPS代理:", self.https_proxy)
        #
        # proxy_layout.addWidget(proxy_group)

        # 添加到选项卡
        tab_widget.addTab(general_tab, "常规设置")
        tab_widget.addTab(regex_tab, "正则表达式配置")
        # tab_widget.addTab(proxy_tab, "代理设置")

        layout.addWidget(tab_widget)

        self.load_regex_config()

    # def create_stats_tab(self):
    #     """创建统计信息标签页"""
    #     tab = QWidget()
    #     self.workspace.addTab(tab, QIcon("ico/stats.png"), "统计分析")
    #     self.tabs["stats"] = tab
    #
    #     layout = QVBoxLayout(tab)
    #
    #     # 控制按钮
    #     btn_layout = QHBoxLayout()
    #     self.refresh_stats_btn = QPushButton(QIcon("ico/refresh.png"), "刷新统计")
    #     self.refresh_stats_btn.clicked.connect(self.update_stats_display)
    #     self.export_stats_btn = QPushButton(QIcon("ico/export.png"), "导出统计")
    #     self.export_stats_btn.clicked.connect(self.export_stats)
    #     btn_layout.addWidget(self.refresh_stats_btn)
    #     btn_layout.addWidget(self.export_stats_btn)
    #     layout.addLayout(btn_layout)
    #
    #     # 统计信息显示区域
    #     stats_splitter = QSplitter(Qt.Orientation.Vertical)
    #
    #     # URL统计表格
    #     url_group = QGroupBox("URL访问统计")
    #     self.url_table = QTableWidget()
    #     self.url_table.setColumnCount(6)
    #     self.url_table.setHorizontalHeaderLabels(["URL", "访问次数", "状态码", "来源IP", "方法", "UA"])
    #     self.url_table.setColumnWidth(0, 400)
    #     self.url_table.horizontalHeader().setStretchLastSection(True)
    #     url_layout = QVBoxLayout(url_group)
    #     url_layout.addWidget(self.url_table)
    #     stats_splitter.addWidget(url_group)
    #
    #     # 状态码统计图表
    #     status_group = QGroupBox("状态码分布")
    #     self.status_chart_view = QChartView()
    #     self.status_chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
    #     status_layout = QVBoxLayout(status_group)
    #     status_layout.addWidget(self.status_chart_view)
    #     stats_splitter.addWidget(status_group)
    #
    #     # IP统计图表
    #     ip_group = QGroupBox("来源IP统计")
    #     self.ip_chart_view = QChartView()
    #     self.ip_chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
    #     ip_layout = QVBoxLayout(ip_group)
    #     ip_layout.addWidget(self.ip_chart_view)
    #     stats_splitter.addWidget(ip_group)
    #
    #     layout.addWidget(stats_splitter)
    #     tab.setLayout(layout)
    def create_stats_tab(self):
        """创建统计信息标签页 - 深色主题"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/stats.png"), "统计分析")
        self.tabs["stats"] = tab
        tab.setStyleSheet("background-color: #1E1E1E;")

        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # 控制按钮区域
        control_panel = QWidget()
        control_panel.setStyleSheet("background-color: #252525; border-radius: 6px; padding: 10px;")
        btn_layout = QHBoxLayout(control_panel)
        btn_layout.setContentsMargins(5, 5, 5, 5)

        btn_style = """
        QPushButton {
            padding: 8px 15px;
            border-radius: 4px;
            font-size: 13px;
            border: none;
            color: white;
            background-color: #3A3A3A;
        }
        QPushButton:hover {
            background-color: #4A4A4A;
        }
        QPushButton:pressed {
            background-color: #2A2A2A;
        }
        QPushButton:disabled {
            background-color: #333333;
            color: #777777;
        }
        """

        self.refresh_stats_btn = QPushButton(QIcon("ico/replay.png"), "刷新统计")
        self.refresh_stats_btn.setStyleSheet(btn_style)
        self.refresh_stats_btn.clicked.connect(self.update_stats_display)

        self.export_stats_btn = QPushButton(QIcon("ico/export.png"), "导出统计")
        self.export_stats_btn.setStyleSheet(btn_style)
        self.export_stats_btn.clicked.connect(self.export_stats)

        btn_layout.addWidget(self.refresh_stats_btn)
        btn_layout.addWidget(self.export_stats_btn)
        btn_layout.addStretch()
        layout.addWidget(control_panel)

        self.fullscreen_manager = FullscreenManager(self)

        # URL访问统计表格
        url_group = QGroupBox("URL访问统计")
        url_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #2D2D2D;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
                color: #AAAAAA;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)

        self.url_table = QTableWidget()
        self.url_table.setColumnCount(6)
        self.url_table.setHorizontalHeaderLabels(["URL", "访问次数", "状态码", "来源IP", "方法", "UA"])
        #self.url_table.setColumnWidth(0, 700)
        self.url_table.horizontalHeader().setStretchLastSection(True)
        self.url_table.setStyleSheet("""
            /* 整体表格样式 */
            QTableWidget {
                border: none; /* 无边框 */
                background-color: #252525; /* 背景色：深灰 */
                alternate-background-color: #2D2D2D; /* 交替行颜色 */
                selection-background-color: #3A3A3A; /* 选中时的背景色（备用，item:selected里也有） */
                color: #DDDDDD; /* 默认字体颜色 */
            }

            /* 表头样式 */
            QHeaderView::section {
                background-color: #2D2D2D; /* 表头背景色 */
                padding: 10px; /* 表头内边距 */
                border: none; /* 无边框 */
                font-weight: bold; /* 字体加粗 */
                color: #AAAAAA; /* 表头字体颜色 */
            }

            /* 单元格普通状态样式 */
            QTableWidget::item {
                border-bottom: 1px solid #0078D7; /* 单元格底部分隔线 */
            }

            /* 单元格选中状态样式 */
            QTableWidget::item:selected {
                background-color: #0078D7; /* 选中时背景色：亮蓝色 */
                color: white; /* 选中时字体颜色 */
            }
        """)

        self.url_table.verticalHeader().setVisible(False)

        url_header = QWidget(url_group)
        url_header.setObjectName("qt_groupbox_titlewidget")
        url_header_layout = QHBoxLayout(url_header)
        url_header_layout.setContentsMargins(0, 0, 0, 0)
        url_title = QLabel("全屏")
        url_title.setStyleSheet("font-weight: bold; color: #AAAAAA;")
        url_header_layout.addWidget(url_title)
        url_header_layout.addStretch()

        url_fullscreen_btn = QToolButton()
        url_fullscreen_btn.setIcon(QIcon("ico/fullscreen.png"))
        url_fullscreen_btn.setStyleSheet("border: none; padding: 0; background-color: transparent; color: #AAAAAA;")
        url_fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        url_fullscreen_btn.clicked.connect(
            lambda: self.fullscreen_manager.enter_fullscreen(self.url_table, "URL访问统计"))
        url_header_layout.addWidget(url_fullscreen_btn)

        url_group.setLayout(QVBoxLayout())
        url_group.layout().addWidget(url_header)
        url_group.layout().addWidget(self.url_table)
        layout.addWidget(url_group)

        # 图表部分 - 横向滑动
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("background-color: transparent;")

        charts_container = QWidget()
        charts_container.setMinimumWidth(1600)  # 设置宽度，确保内容超出可视区域时显示滚动条
        charts_layout = QHBoxLayout(charts_container)
        charts_layout.setSpacing(15)
        charts_layout.setContentsMargins(10, 10, 10, 10)

        def create_chart_group(title, chart_view):
            group = QGroupBox(title)
            group.setStyleSheet(url_group.styleSheet())

            chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
            chart_view.setStyleSheet("background-color: transparent; border: none;")

            header = QWidget(group)
            header.setObjectName("qt_groupbox_titlewidget")
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(0, 0, 0, 0)
            header_title = QLabel("全屏")
            header_title.setStyleSheet("font-weight: bold; color: #AAAAAA;")
            header_layout.addWidget(header_title)
            header_layout.addStretch()

            fullscreen_btn = QToolButton()
            fullscreen_btn.setIcon(QIcon("ico/fullscreen.png"))
            fullscreen_btn.setStyleSheet("border: none; padding: 0;")
            fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            fullscreen_btn.clicked.connect(lambda: self.fullscreen_manager.enter_fullscreen(chart_view, title))
            header_layout.addWidget(fullscreen_btn)

            group.setLayout(QVBoxLayout())
            group.layout().addWidget(header)
            group.layout().addWidget(chart_view)
            return group

        self.status_chart_view = QChartView()
        self.ip_chart_view = QChartView()

        self.time_chart_view = QChartView()
        self.uri_chart_view = QChartView()

        charts_layout.addWidget(create_chart_group("状态码分布", self.status_chart_view))
        charts_layout.addWidget(create_chart_group("来源IP统计", self.ip_chart_view))
        charts_layout.addWidget(create_chart_group("访问时间趋势", self.time_chart_view))
        charts_layout.addWidget(create_chart_group("URI访问统计", self.uri_chart_view))

        scroll_area.setWidget(charts_container)
        layout.addWidget(scroll_area)

        return tab

    # def create_stats_tab(self):
    #     """创建统计信息标签页 - 深色主题"""
    #     tab = QWidget()
    #     self.workspace.addTab(tab, QIcon("ico/stats.png"), "统计分析")
    #     self.tabs["stats"] = tab
    #     tab.setStyleSheet("background-color: #1E1E1E;")
    #
    #     # 主布局
    #     layout = QVBoxLayout(tab)
    #     layout.setContentsMargins(15, 15, 15, 15)
    #     layout.setSpacing(15)
    #
    #     # 控制按钮区域
    #     control_panel = QWidget()
    #     control_panel.setStyleSheet("background-color: #252525; border-radius: 6px; padding: 10px;")
    #     btn_layout = QHBoxLayout(control_panel)
    #     btn_layout.setContentsMargins(5, 5, 5, 5)
    #
    #     # 按钮样式
    #     btn_style = """
    #     QPushButton {
    #         padding: 8px 15px;
    #         border-radius: 4px;
    #         font-size: 13px;
    #         border: none;
    #         color: white;
    #         background-color: #3A3A3A;
    #     }
    #     QPushButton:hover {
    #         background-color: #4A4A4A;
    #     }
    #     QPushButton:pressed {
    #         background-color: #2A2A2A;
    #     }
    #     QPushButton:disabled {
    #         background-color: #333333;
    #         color: #777777;
    #     }
    #     """
    #
    #     self.refresh_stats_btn = QPushButton(QIcon("ico/replay.png"), "刷新统计")
    #     self.refresh_stats_btn.setStyleSheet(btn_style)
    #     self.refresh_stats_btn.clicked.connect(self.update_stats_display)
    #
    #     self.export_stats_btn = QPushButton(QIcon("ico/export.png"), "导出统计")
    #     self.export_stats_btn.setStyleSheet(btn_style)
    #     self.export_stats_btn.clicked.connect(self.export_stats)
    #
    #     btn_layout.addWidget(self.refresh_stats_btn)
    #     btn_layout.addWidget(self.export_stats_btn)
    #     btn_layout.addStretch()
    #
    #     layout.addWidget(control_panel)
    #
    #     # 创建全屏管理器
    #     self.fullscreen_manager = FullscreenManager(self)
    #
    #     # URL统计表格（固定）
    #     url_group = QGroupBox("URL访问统计")
    #     # url_group.setStyleSheet("""
    #     #     QGroupBox {
    #     #         border: 1px solid #2D2D2D;
    #     #         border-radius: 8px;
    #     #         margin-top: 10px;
    #     #         padding-top: 15px;
    #     #         font-weight: bold;
    #     #         background-color: #252525;
    #     #         color: #AAAAAA;
    #     #     }
    #     #     QGroupBox::title {
    #     #         subcontrol-origin: margin;
    #     #         left: 10px;
    #     #         padding: 0 5px;
    #     #     }
    #     # """)
    #     url_group.setStyleSheet("""
    #         QGroupBox {
    #             border: 1px solid #2D2D2D;
    #             border-radius: 8px;
    #             margin-top: 10px;
    #             padding-top: 15px;
    #             font-weight: bold;
    #
    #             color: #AAAAAA;
    #         }
    #         QGroupBox::title {
    #             subcontrol-origin: margin;
    #             left: 10px;
    #             padding: 0 5px;
    #         }
    #     """)
    #     self.url_table = QTableWidget()
    #     self.url_table.setColumnCount(6)
    #     self.url_table.setHorizontalHeaderLabels(["URL", "访问次数", "状态码", "来源IP", "方法", "UA"])
    #     self.url_table.setColumnWidth(0, 400)
    #     self.url_table.horizontalHeader().setStretchLastSection(True)
    #     self.url_table.setStyleSheet("""
    #         QTableWidget {
    #             border: none;
    #             background-color: #252525;
    #             alternate-background-color: #2D2D2D;
    #             selection-background-color: #3A3A3A;
    #             color: #DDDDDD;
    #         }
    #         QHeaderView::section {
    #             background-color: #2D2D2D;
    #             padding: 10px;
    #             border: none;
    #             font-weight: bold;
    #             color: #AAAAAA;
    #         }
    #         QTableWidget::item {
    #             padding: 8px;
    #             border-bottom: 1px solid #3A3A3A;
    #         }
    #         QTableWidget::item:selected {
    #             background-color: #3A3A3A;
    #             color: white;
    #         }
    #     """)
    #     self.url_table.verticalHeader().setVisible(False)
    #
    #     # 添加全屏按钮到URL表格
    #     url_header = url_group.findChild(QWidget, "qt_groupbox_titlewidget")
    #     if url_header is None:
    #         url_header = QWidget(url_group)
    #         url_header.setObjectName("qt_groupbox_titlewidget")
    #
    #     url_header_layout = QHBoxLayout(url_header)
    #     url_header_layout.setContentsMargins(0, 0, 0, 0)
    #     url_title = QLabel("全屏")
    #     url_title.setStyleSheet("font-weight: bold; color: #AAAAAA;")
    #     url_header_layout.addWidget(url_title)
    #     url_header_layout.addStretch()  # 将空间放到标题和按钮之间，使按钮靠右
    #
    #     url_fullscreen_btn = QToolButton()
    #     url_fullscreen_btn.setIcon(QIcon("ico/fullscreen.png"))
    #     url_fullscreen_btn.setStyleSheet("""
    #         border: none;
    #         padding: 0;
    #         background-color: transparent;
    #         color: #AAAAAA;
    #     """)
    #     url_fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    #     url_fullscreen_btn.clicked.connect(lambda: self.fullscreen_manager.enter_fullscreen(self.url_table, "URL访问统计"))
    #     url_header_layout.addWidget(url_fullscreen_btn)
    #
    #     url_group.setLayout(QVBoxLayout())
    #     url_group.layout().addWidget(url_header)
    #     url_group.layout().addWidget(self.url_table)
    #     layout.addWidget(url_group)
    #
    #     # 图表容器 + 滚动区域
    #     scroll_area = QScrollArea()
    #     scroll_area.setWidgetResizable(True)
    #     scroll_area.setStyleSheet("background-color: transparent;")
    #
    #     charts_container = QWidget()
    #     charts_layout = QGridLayout(charts_container)
    #     charts_layout.setSpacing(15)
    #     charts_layout.setContentsMargins(10, 10, 10, 10)
    #
    #     # 状态码统计图
    #     status_group = QGroupBox("状态码分布")
    #     status_group.setStyleSheet(url_group.styleSheet())
    #     self.status_chart_view = QChartView()
    #     self.status_chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
    #     self.status_chart_view.setStyleSheet("background-color: transparent; border: none;")
    #
    #     # 添加全屏按钮到状态码图表
    #     status_header = QWidget(status_group)
    #     status_header.setObjectName("qt_groupbox_titlewidget")
    #     status_header_layout = QHBoxLayout(status_header)
    #     status_header_layout.setContentsMargins(0, 0, 0, 0)
    #     status_title = QLabel("全屏")
    #     status_title.setStyleSheet("font-weight: bold; color: #AAAAAA;")
    #     status_header_layout.addWidget(status_title)
    #     status_header_layout.addStretch()
    #
    #     status_fullscreen_btn = QToolButton()
    #     status_fullscreen_btn.setIcon(QIcon("ico/fullscreen.png"))
    #     status_fullscreen_btn.setStyleSheet("border: none; padding: 0;")
    #     status_fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    #     status_fullscreen_btn.clicked.connect(
    #         lambda: self.fullscreen_manager.enter_fullscreen(self.status_chart_view, "状态码分布"))
    #     status_header_layout.addWidget(status_fullscreen_btn)
    #
    #     status_group.setLayout(QVBoxLayout())
    #     status_group.layout().addWidget(status_header)
    #     status_group.layout().addWidget(self.status_chart_view)
    #
    #     # 来源IP统计图
    #     ip_group = QGroupBox("来源IP统计")
    #     ip_group.setStyleSheet(url_group.styleSheet())
    #     self.ip_chart_view = QChartView()
    #     self.ip_chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
    #     self.ip_chart_view.setStyleSheet("background-color: transparent; border: none;")
    #
    #     # 添加全屏按钮到IP图表
    #     ip_header = QWidget(ip_group)
    #     ip_header.setObjectName("qt_groupbox_titlewidget")
    #     ip_header_layout = QHBoxLayout(ip_header)
    #     ip_header_layout.setContentsMargins(0, 0, 0, 0)
    #     ip_title = QLabel("全屏")
    #     ip_title.setStyleSheet("font-weight: bold; color: #AAAAAA;")
    #     ip_header_layout.addWidget(ip_title)
    #     ip_header_layout.addStretch()
    #
    #     ip_fullscreen_btn = QToolButton()
    #     ip_fullscreen_btn.setIcon(QIcon("ico/fullscreen.png"))
    #     ip_fullscreen_btn.setStyleSheet("border: none; padding: 0;")
    #     ip_fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    #     ip_fullscreen_btn.clicked.connect(
    #         lambda: self.fullscreen_manager.enter_fullscreen(self.ip_chart_view, "来源IP统计"))
    #     ip_header_layout.addWidget(ip_fullscreen_btn)
    #
    #     ip_group.setLayout(QVBoxLayout())
    #     ip_group.layout().addWidget(ip_header)
    #     ip_group.layout().addWidget(self.ip_chart_view)
    #
    #     # 时间趋势图
    #     time_group = QGroupBox("访问时间趋势")
    #     time_group.setStyleSheet(url_group.styleSheet())
    #     self.time_chart_view = QChartView()
    #     self.time_chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
    #     self.time_chart_view.setStyleSheet("background-color: transparent; border: none;")
    #
    #     # 添加全屏按钮到时间趋势图
    #     time_header = QWidget(time_group)
    #     time_header.setObjectName("qt_groupbox_titlewidget")
    #     time_header_layout = QHBoxLayout(time_header)
    #     time_header_layout.setContentsMargins(0, 0, 0, 0)
    #     time_title = QLabel("全屏")
    #     time_title.setStyleSheet("font-weight: bold; color: #AAAAAA;")
    #     time_header_layout.addWidget(time_title)
    #     time_header_layout.addStretch()
    #
    #     time_fullscreen_btn = QToolButton()
    #     time_fullscreen_btn.setIcon(QIcon("ico/fullscreen.png"))
    #     time_fullscreen_btn.setStyleSheet("border: none; padding: 0;")
    #     time_fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    #     time_fullscreen_btn.clicked.connect(
    #         lambda: self.fullscreen_manager.enter_fullscreen(self.time_chart_view, "访问时间趋势"))
    #     time_header_layout.addWidget(time_fullscreen_btn)
    #
    #     time_group.setLayout(QVBoxLayout())
    #     time_group.layout().addWidget(time_header)
    #     time_group.layout().addWidget(self.time_chart_view)
    #
    #     # URI统计图
    #     uri_group = QGroupBox("URI访问统计")
    #     uri_group.setStyleSheet(url_group.styleSheet())
    #     self.uri_chart_view = QChartView()
    #     self.uri_chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
    #     self.uri_chart_view.setStyleSheet("background-color: transparent; border: none;")
    #
    #     # 添加全屏按钮到URI统计图
    #     uri_header = QWidget(uri_group)
    #     uri_header.setObjectName("qt_groupbox_titlewidget")
    #     uri_header_layout = QHBoxLayout(uri_header)
    #     uri_header_layout.setContentsMargins(0, 0, 0, 0)
    #     uri_title = QLabel("全屏")
    #     uri_title.setStyleSheet("font-weight: bold; color: #AAAAAA;")
    #     uri_header_layout.addWidget(uri_title)
    #     uri_header_layout.addStretch()
    #
    #     uri_fullscreen_btn = QToolButton()
    #     uri_fullscreen_btn.setIcon(QIcon("ico/fullscreen.png"))
    #     uri_fullscreen_btn.setStyleSheet("border: none; padding: 0;")
    #     uri_fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    #     uri_fullscreen_btn.clicked.connect(lambda: self.fullscreen_manager.enter_fullscreen(self.uri_chart_view, "URI访问统计"))
    #     uri_header_layout.addWidget(uri_fullscreen_btn)
    #
    #     uri_group.setLayout(QVBoxLayout())
    #     uri_group.layout().addWidget(uri_header)
    #     uri_group.layout().addWidget(self.uri_chart_view)
    #
    #     # 将图表加入布局
    #     charts_layout.addWidget(status_group, 0, 0)
    #     charts_layout.addWidget(ip_group, 0, 1)
    #     charts_layout.addWidget(time_group, 1, 0)
    #     charts_layout.addWidget(uri_group, 1, 1)
    #
    #     scroll_area.setWidget(charts_container)
    #     layout.addWidget(scroll_area)
    #
    #     return tab


    def load_regex_config(self):
        """加载正则表达式配置"""
        category = self.regex_category.currentText()

        try:
            if category == "日志格式识别":
                self.current_config = self.config.get("log_formats", {})
            elif category == "日志解析":

                self.current_config = self.config.get("parsers", {})
            elif category == "安全检测":
                self.current_config = self.config.get("safety_testing", {})

            # 更新规则名称下拉框
            self.rule_name_combo.clear()

            self.rule_name_combo.addItems(list(self.current_config.keys()))

            if self.rule_name_combo.count() > 0:
                self.rule_name_combo.setCurrentIndex(0)
                self.load_selected_rule()
        except Exception as e:
            QMessageBox.warning(self, "警告", f"加载正则表达式配置失败: {str(e)}")

    def load_selected_rule(self):
        """加载选中的规则"""
        rule_name = self.rule_name_combo.currentText()
        if not rule_name or not self.current_config:
            return

        try:
            rule_data = self.current_config[rule_name]

            if isinstance(rule_data, dict):
                # 处理安全检测的多规则情况
                self.rule_name_edit.setText(rule_name)
                self.regex_edit.setPlainText("\n".join(rule_data.get("rules", [])))
            elif isinstance(rule_data, str):
                # 处理简单规则
                self.rule_name_edit.setText(rule_name)
                self.regex_edit.setPlainText(rule_data)
            elif isinstance(rule_data, list):
                # 处理多行规则
                self.rule_name_edit.setText(rule_name)
                self.regex_edit.setPlainText("\n".join(rule_data))
        except Exception as e:
            QMessageBox.warning(self, "警告", f"加载规则失败: {str(e)}")

    def save_regex_config(self):
        """保存正则表达式配置"""
        rule_name = self.rule_name_edit.text().strip()
        if not rule_name:
            QMessageBox.warning(self, "警告", "请输入规则名称!")
            return

        regex_text = self.regex_edit.toPlainText().strip()
        if not regex_text:
            QMessageBox.warning(self, "警告", "请输入正则表达式!")
            return

        try:
            # 更新当前配置
            if self.regex_category.currentText() == "安全检测":
                # 安全检测规则是字典结构
                if rule_name not in self.current_config:
                    self.current_config[rule_name] = {"name": [], "rules": []}

                # 分割多行正则
                rules = [r.strip() for r in regex_text.split("\n") if r.strip()]
                self.current_config[rule_name]["rules"] = rules
            else:
                # 其他规则可以是字符串或多行
                rules = [r.strip() for r in regex_text.split("\n") if r.strip()]
                self.current_config[rule_name] = rules[0] if len(rules) == 1 else rules

            # 更新主配置
            category = self.regex_category.currentText()
            if category == "日志格式识别":
                self.config["log_formats"] = self.current_config
            elif category == "日志解析":
                self.config["parsers"] = self.current_config
            elif category == "安全检测":
                self.config["safety_testing"] = self.current_config

            # 保存到文件
            with open("config.yaml", "w", encoding="utf-8") as f:
                yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)

            # 更新下拉框
            self.load_regex_config()
            QMessageBox.information(self, "成功", "配置已保存!")
        except Exception as e:
            QMessageBox.warning(self, "警告", f"保存配置失败: {str(e)}")

    def add_new_rule(self):
        """添加新规则"""
        rule_name, ok = QInputDialog.getText(self, "添加新规则", "请输入规则名称:")
        if not ok or not rule_name.strip():
            return

        if rule_name in self.current_config:
            QMessageBox.warning(self, "警告", "规则名称已存在!")
            return

        try:
            # 初始化新规则
            if self.regex_category.currentText() == "安全检测":
                self.current_config[rule_name] = {"name": [rule_name], "rules": [""]}
            else:
                self.current_config[rule_name] = ""

            # 更新UI
            self.rule_name_combo.addItem(rule_name)
            self.rule_name_combo.setCurrentText(rule_name)
            self.rule_name_edit.setText(rule_name)
            self.regex_edit.clear()
        except Exception as e:
            QMessageBox.warning(self, "警告", f"添加规则失败: {str(e)}")

    def delete_rule(self):
        """删除规则"""
        rule_name = self.rule_name_combo.currentText()
        if not rule_name:
            return

        reply = QMessageBox.question(
            self, "确认删除",
            f"确定要删除规则 '{rule_name}' 吗?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # 从当前配置中删除
                del self.current_config[rule_name]

                # 更新主配置
                category = self.regex_category.currentText()
                if category == "日志格式识别":
                    self.config["log_formats"] = self.current_config
                elif category == "日志解析":
                    self.config["parsers"] = self.current_config
                elif category == "安全检测":
                    self.config["safety_testing"] = self.current_config

                # 保存到文件
                with open("config.yaml", "w", encoding="utf-8") as f:
                    yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)

                # 更新UI
                self.load_regex_config()
                QMessageBox.information(self, "成功", "规则已删除!")
            except Exception as e:
                QMessageBox.warning(self, "警告", f"删除规则失败: {str(e)}")

    def test_regex(self):
        """测试正则表达式"""
        regex_text = self.regex_edit.toPlainText().strip()
        if not regex_text:
            QMessageBox.warning(self, "警告", "请输入正则表达式!")
            return

        test_text = self.test_input.toPlainText()
        test_text = test_text.replace('＂', '"')  # 清理空白和全角引号
        if not test_text:
            QMessageBox.warning(self, "警告", "请输入测试文本!")
            return

        try:
            # 测试单行正则
            if "\n" not in regex_text:

                pattern = re.compile(regex_text)
                matches = pattern.findall(test_text)

                if matches:
                    self.test_output.setPlainText(f"匹配成功!\n找到 {len(matches)} 处匹配:\n{matches}")
                else:
                    self.test_output.setPlainText("没有找到匹配!")
            else:
                # 测试多行正则
                results = []
                for line in regex_text.split("\n"):
                    if line.strip():
                        pattern = re.compile(line.strip())
                        matches = pattern.findall(test_text)
                        if matches:
                            results.append(f"正则: {line}\n匹配结果: {matches}\n")

                if results:
                    self.test_output.setPlainText("匹配成功!\n\n" + "\n".join(results))
                else:
                    self.test_output.setPlainText("没有找到匹配!")
        except re.error as e:
            self.test_output.setPlainText(f"正则表达式错误: {str(e)}")
        except Exception as e:
            self.test_output.setPlainText(f"测试时发生错误: {str(e)}")

    def check_for_updates(self):
        """检查更新"""
        try:
            # 这里可以添加实际的更新检查逻辑
            QMessageBox.information(self, "检查更新", "当前已是最新版本!")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"检查更新失败: {str(e)}")

    def create_replay_tab(self):
        """创建请求重放选项卡"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/replay.png"), "请求重放")
        self.tabs["replay"] = tab

        # 主布局使用垂直分割器（上部分控制面板，下部分结果显示）
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # ==================== 上部控制面板 ====================
        top_panel = QWidget()
        top_layout = QVBoxLayout(top_panel)
        top_layout.setContentsMargins(5, 5, 5, 5)
        top_layout.setSpacing(10)

        # 第一行：文件选择和会话ID
        row1 = QHBoxLayout()

        # 会话ID区域（宽度40%）
        stream_id_group = QGroupBox("会话ID")
        stream_id_layout = QHBoxLayout(stream_id_group)
        self.stream_id_input = QLineEdit()
        self.stream_id_input.setPlaceholderText("输入请求会话ID...")
        stream_id_layout.addWidget(self.stream_id_input)

        self.find_request_button = QPushButton("输出ID")
        self.find_request_button.setFixedWidth(80)
        self.find_request_button.setStyleSheet("background-color: #4CAF50;")
        self.find_request_button.clicked.connect(self.find_request)
        stream_id_layout.addWidget(self.find_request_button)
        row1.addWidget(stream_id_group, stretch=2)

        top_layout.addLayout(row1)

        # 第二行：分析方式和代理设置
        row2 = QHBoxLayout()

        # 分析方式选择（宽度50%）
        method_group = QGroupBox("分析方式")
        method_layout = QHBoxLayout(method_group)
        self.replay_pyshark_radio = QRadioButton("pyshark (Python库)")
        self.replay_pyshark_radio.setStyleSheet("""
            QRadioButton::indicator {

                border: 2px solid #007BFF;
                border-radius: 8px;
                background-color: transparent;
            }
            QRadioButton::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
        """)

        self.replay_tshark_radio = QRadioButton("tshark")
        self.replay_tshark_radio.setChecked(True)
        self.replay_tshark_radio.setStyleSheet("""
            QRadioButton::indicator {

                border: 2px solid #007BFF;
                border-radius: 8px;
                background-color: transparent;
            }
            QRadioButton::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
        """)
        method_layout.addWidget(self.replay_pyshark_radio)
        method_layout.addWidget(self.replay_tshark_radio)
        row2.addWidget(method_group, stretch=1)

        # 代理设置（宽度50%）
        self.proxy_group = QGroupBox("代理设置")
        self.proxy_group.setCheckable(True)
        self.proxy_group.setChecked(True)
        self.proxy_group.toggled.connect(self.toggle_proxy_settings)
        proxy_layout = QHBoxLayout(self.proxy_group)

        self.http_proxy_input = QLineEdit()
        self.http_proxy_input.setPlaceholderText("HTTP代理")
        self.http_proxy_input.setText("http://127.0.0.1:8080")
        self.http_proxy_input.setEnabled(False)
        self.http_proxy_input.setMinimumWidth(150)

        self.https_proxy_input = QLineEdit()
        self.https_proxy_input.setPlaceholderText("HTTPS代理")
        self.https_proxy_input.setText("http://127.0.0.1:8080")
        self.https_proxy_input.setEnabled(False)
        self.https_proxy_input.setMinimumWidth(150)

        proxy_layout.addWidget(self.http_proxy_input)
        proxy_layout.addWidget(self.https_proxy_input)
        row2.addWidget(self.proxy_group, stretch=1)

        top_layout.addLayout(row2)

        # 第三行：操作按钮
        button_group = QGroupBox("操作")
        button_layout = QHBoxLayout(button_group)

        self.replay_button = QPushButton("重放请求")
        self.replay_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
                 /* color: #4CAF50; 字体绿色 */
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        self.replay_button.clicked.connect(self.replay_request)
        self.replay_button.setIcon(QIcon("ico/replay.png"))
        button_layout.addWidget(self.replay_button, stretch=2)

        self.clear_replay_button = QPushButton("清除结果")
        self.clear_replay_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
               /* color: #FFEB3B;   黄色字体 */
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        self.clear_replay_button.clicked.connect(self.clear_replay_results)
        self.clear_replay_button.setIcon(QIcon("ico/clear.png"))
        button_layout.addWidget(self.clear_replay_button, stretch=1)

        self.stop_replay_button = QPushButton("停止")
        self.stop_replay_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
                /*color: #F44336;   红色字体 */
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        self.stop_replay_button.clicked.connect(self.stop_replay)
        self.stop_replay_button.setIcon(QIcon("ico/export.png"))
        self.stop_replay_button.setEnabled(False)
        button_layout.addWidget(self.stop_replay_button, stretch=1)

        top_layout.addWidget(button_group)

        # ==================== 下部结果展示 ====================
        bottom_panel = QGroupBox("请求信息")
        bottom_layout = QVBoxLayout(bottom_panel)

        self.request_text_edit = QTextEdit()
        self.request_text_edit.setPlaceholderText("请求信息将显示在这里...")
        self.request_text_edit.setReadOnly(True)
        self.request_text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        font = self.request_text_edit.font()
        font.setFamily("Consolas")
        font.setPointSize(10)
        self.request_text_edit.setFont(font)

        self.request_text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #3E3E3E;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        bottom_layout.addWidget(self.request_text_edit)
        self.status_create_replay_tab = QLabel("")
        bottom_layout.addWidget(self.status_create_replay_tab)
        # ==================== 添加到主分割器 ====================
        main_splitter.addWidget(top_panel)
        main_splitter.addWidget(bottom_panel)

        # 设置分割器样式和比例
        main_splitter.setStyleSheet("""
            QSplitter::handle {
                background: #3E3E3E;
                height: 1px;
            }
        """)
        main_splitter.setSizes([200, 600])

        # 将分割器设置为主布局
        tab_layout = QVBoxLayout(tab)
        tab_layout.addWidget(main_splitter)

    def toggle_proxy_settings(self, enabled):
        """切换代理设置可用状态"""
        self.http_proxy_input.setEnabled(enabled)
        self.https_proxy_input.setEnabled(enabled)

    def create_log_tab(self):
        """创建日志分析标签页"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/logs.png"), "Log分析")
        self.tabs["log"] = tab

        layout = QVBoxLayout(tab)

        # # 控制面板
        # control_panel = QGroupBox("日志分析控制")
        # control_layout = QHBoxLayout(control_panel)
        #
        # self.log_file_input = QLineEdit()
        # self.log_file_input.setPlaceholderText("选择日志文件...")
        #
        # btn_browse = QPushButton("Log日志文件")
        # btn_clear = QPushButton("清除")
        #
        # # 连接按钮信号
        # btn_browse.clicked.connect(self.browse_log_file)
        # btn_clear.clicked.connect(self.clear_log_analysis)
        #
        # control_layout.addWidget(self.log_file_input)
        # control_layout.addWidget(btn_browse)
        # control_layout.addWidget(btn_clear)
        # layout.addWidget(control_panel)

        # 分析类型按钮面板
        type_analysis_panel = QGroupBox("分析类型")
        type_analysis_layout = QVBoxLayout(type_analysis_panel)

        btn_style = """
             QPushButton {
                 background-color: #3E3E3E;
                 color: #EEE;
                 padding: 6px 12px;
                 border-radius: 6px;
                 font-weight: bold;
             }
             QPushButton:hover {
                 background-color: #5C5C5C;
             }
         """

        # 第一行按钮
        row1 = QHBoxLayout()
        automatic = QPushButton(QIcon("ico/analyze.png"), "自动识别类型分析")
        apache_access = QPushButton(QIcon("ico/Apache.png"), "Apache Access")
        nginx_access = QPushButton(QIcon("ico/Nginx.png"), "Nginx Access")
        json_log = QPushButton(QIcon("ico/json.png"), "JSON Log")

        # 第二行按钮
        row2 = QHBoxLayout()
        f5_healthcheck = QPushButton(QIcon("ico/F5.png"), "F5 HealthCheck")
        haproxy_access = QPushButton(QIcon("ico/Haproxy.png"), "HAProxy Access")
        iis_log = QPushButton(QIcon("ico/IIS.png"), "IIS Log")
        tomcat_access_log = QPushButton(QIcon("ico/Tomcat.png"), "Tomcat Access Log")

        for btn in [automatic, apache_access, nginx_access, json_log,
                    f5_healthcheck, haproxy_access, iis_log, tomcat_access_log]:
            btn.setStyleSheet(btn_style)
            btn.setMinimumHeight(32)

        # 连接分析按钮信号
        automatic.clicked.connect(lambda: self.analyze_logs('auto'))
        apache_access.clicked.connect(lambda: self.analyze_logs('apache_access'))
        nginx_access.clicked.connect(lambda: self.analyze_logs('nginx_access'))
        json_log.clicked.connect(lambda: self.analyze_logs('json_log'))
        f5_healthcheck.clicked.connect(lambda: self.analyze_logs('f5_healthcheck'))
        haproxy_access.clicked.connect(lambda: self.analyze_logs('haproxy_access'))
        iis_log.clicked.connect(lambda: self.analyze_logs('iis_log'))
        tomcat_access_log.clicked.connect(lambda: self.analyze_logs('tomcat_access_log'))

        # 添加按钮到对应行
        for btn in [automatic, apache_access, nginx_access, json_log]:
            row1.addWidget(btn)
        for btn in [f5_healthcheck, haproxy_access, iis_log, tomcat_access_log]:
            row2.addWidget(btn)

        type_analysis_layout.addLayout(row1)
        type_analysis_layout.addLayout(row2)
        layout.addWidget(type_analysis_panel)

        # 结果显示区域
        result_panel = QGroupBox("分析结果")
        result_layout = QVBoxLayout(result_panel)

        # 创建表格控件
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(7)
        self.log_table.setHorizontalHeaderLabels(["URL", "访问次数", "状态码", "来源IP", "方法", "检测危险", "UA"])
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.setSortingEnabled(True)
        self.log_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.log_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # 设置表格样式
        self.log_table.setStyleSheet("""
             QTableWidget {
                 background-color: #252525;
                 color: #EEE;
                 border: 1px solid #444;
                 font-family: Consolas, Courier New, monospace;
                 font-size: 12px;
             }
             QHeaderView::section {
                 background-color: #3A3A3A;
                 color: white;
                 padding: 5px;
                 border: 1px solid #444;
             }
             QTableWidget::item {
                 padding: 5px;
             }
             QTableWidget::item:selected {
                 background-color: #4A6EA9;
             }
         """)

        # 添加导出按钮
        export_btn = QPushButton("导出为CSV")
        export_btn.setStyleSheet("""
             QPushButton {
                 background-color: #4A4A4A;
                 color: white;
                 border: none;
                 border-radius: 4px;
                 padding: 8px 16px;
                 min-width: 80px;
             }
             QPushButton:hover {
                 background-color: #5A5A5A;
             }
         """)
        export_btn.clicked.connect(self.export_log_table)

        result_layout.addWidget(self.log_table)
        result_layout.addWidget(export_btn)
        layout.addWidget(result_panel)

    def browse_log_file(self):
        """浏览并选择日志文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择日志文件",
            "",
            "日志文件 (*.log *.txt);;所有文件 (*)"
        )
        if file_path:
            self.log_file_input.setText(file_path)
            self.add_recent_activity("打开文件", file_path, "打开文件")

    def clear_log_analysis(self):
        """清除日志分析内容"""
        # self.log_file_input.clear()
        self.log_table.setRowCount(0)

    def analyze_logs(self, log_type=None, ai_analysis_starts=None):
        """分析日志文件"""
        file_path = self.Import_box.text().strip()
        if not file_path.lower().endswith(('.log', '.txt')):
            QMessageBox.warning(self, "警告", "请选择正确的.log文件或者.txt文件!")
            return

        if not file_path:
            QMessageBox.warning(self, "警告", "请先选择日志文件!")
            return

        try:
            self.add_recent_activity("开始分析LOG日志", file_path, "运行中")
            self.log_table.setRowCount(0)

            self.url_stats = defaultdict(lambda: {
                'count': 0,
                'status_codes': defaultdict(int),
                'source_ips': defaultdict(int),
                'methods': defaultdict(int),
                'request_time': defaultdict(int),
                'UA': defaultdict(int),
                "danger": defaultdict(int),
            })

            # 根据不同类型调用不同的解析方法
            if log_type == 'auto':
                # 检测什么类型的 日志
                detected_type = log_identification.guess_log_format(file_path)
                self.status_label.setText("自动检测到日志类型LOG分析：" + detected_type+" ———————— 【每隔5秒后刷新统计】【注意！在刷新的时候界面会卡顿】")
                self.log_table.setItem(0, 0, QTableWidgetItem(f"自动检测到日志类型: {detected_type}"))
                log_type = detected_type

            # 创建并启动工作线程
            self.worker_thread = LogProcessingThread(file_path, log_type,self.url_stats,ai_analysis_starts)
            self.worker_thread.finished.connect(self.on_log_processing_finished)
            self.worker_thread.error.connect(self.on_log_processing_error)
            self.worker_thread.start()

            # 创建并启动UI更新定时器
            self.ui_update_timer = QTimer()
            self.ui_update_timer.timeout.connect(self.update_ui_periodically)
            self.ui_update_timer.start(5000)  # 每5秒更新一次UI


        except Exception as e:
            self.log_table.setItem(0, 0, QTableWidgetItem(f"分析日志时出错: {str(e)}"))

    def update_ui_periodically(self):
        """定期更新UI的函数"""
        try:
            # 计算当前总请求数
            total_requests = sum(stats['count'] for stats in self.url_stats.values())
            # 动态调整刷新间隔
            if total_requests > 1400000:
                new_interval = 75000  # 75秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 1000000:
                new_interval = 60000  # 75秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 800000:
                new_interval = 40000  # 40秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 600000:
                new_interval = 30000  # 30秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 500000:
                new_interval = 25000  # 25秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 400000:
                new_interval = 20000  # 20秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 300000:
                new_interval = 15000  # 15秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 200000:
                new_interval = 12000  # 12秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            # 动态调整刷新间隔
            elif total_requests > 100000:
                new_interval = 9000  # 9秒
                if self.ui_update_timer.interval() != new_interval:
                    self.ui_update_timer.setInterval(new_interval)
                    self.status_label.setText(f"数据{total_requests}较大，已自动调整刷新间隔为{new_interval // 1000}秒-----【注意！在刷新的时候界面会卡顿】")
            else:
                if self.ui_update_timer.interval() != 5000:  # 恢复默认5秒
                    self.ui_update_timer.setInterval(5000)

            self.update_stats_display()
            self.parse_web_server_log()
            self.update_dashboard_stats()
        except Exception as e:
            print(f"更新UI时出错: {str(e)}")
    def on_log_processing_finished(self, url_stats,ai_analysis_starts):
        """日志处理完成回调"""
        # 停止UI更新定时器
        if hasattr(self, 'ui_update_timer') and self.ui_update_timer.isActive():
            self.ui_update_timer.stop()
            # 重置为默认间隔（避免下次分析时继承上次的间隔）
            self.ui_update_timer.setInterval(5000)

        self.update_stats_display()
        self.parse_web_server_log()
        self.update_dashboard_stats()

        if ai_analysis_starts:
            ai_analysis_starts["request"]['log'] = [uri for uri in self.url_stats]
            self.ai_analysis_preparation(ai_analysis_starts)

        self.add_recent_activity("LOG分析完成", self.Import_box.text().strip(),
                                 f"分析成功完成一共：{sum(stats['count'] for stats in self.url_stats.values())}请求，唯一URI：{len(self.url_stats)}")
        self.status_label.setText("LOG分析完成")

    def on_log_processing_error(self, error_msg):
        """日志处理错误回调"""
        # 停止UI更新定时器
        if hasattr(self, 'ui_update_timer') and self.ui_update_timer.isActive():
            self.ui_update_timer.stop()
        self.log_table.setItem(0, 0, QTableWidgetItem(f"分析日志时出错: {error_msg}"))
        self.status_label.setText("日志分析出错")
    # def analyze_logs(self, log_type=None, ai_analysis_starts=None):
    #     """分析日志文件"""
    #     file_path = self.Import_box.text().strip()  # 这样当两个输入栏都有内容时，会优先使用 self.log_file_input 中的内容，否则再使用 self.Import_box 的内容
    #     if not file_path.lower().endswith(('.log', '.txt')):
    #         QMessageBox.warning(self, "警告", "请选择正确的.log文件或者.txt文件!")
    #         return
    #     if not file_path:
    #         file_path = self.Import_box.text().strip()
    #
    #     if not file_path:
    #         QMessageBox.warning(self, "警告", "请先选择日志文件!")
    #         return
    #
    #     try:
    #         self.add_recent_activity("开始分析LOG日志", file_path, "运行中")
    #
    #         # 清空表格
    #         self.url_stats = defaultdict(lambda: {
    #             'count': 0,
    #             'status_codes': defaultdict(int),
    #             'source_ips': defaultdict(int),
    #             'methods': defaultdict(int),
    #             'request_time': defaultdict(int),
    #             'UA': defaultdict(int),
    #             "danger": defaultdict(int),
    #         })
    #         self.log_table.setRowCount(0)
    #
    #         # 根据不同类型调用不同的解析方法
    #         if log_type == 'auto':
    #             # 检测什么类型的 日志
    #             detected_type = log_identification.guess_log_format(file_path)
    #             self.status_label.setText("自动检测到日志类型LOG分析：" + detected_type)
    #             self.log_table.setItem(0, 0, QTableWidgetItem(f"自动检测到日志类型: {detected_type}"))
    #             log_type = detected_type
    #
    #         log_identification.process_log_file(file_path, self.url_stats, log_type)
    #
    #         if not self.url_stats:
    #             self.add_recent_activity("LOG分析", file_path, f"分析可能失败结果是0，结果不匹配可能")
    #             self.status_label.setText("分析可能失败结果是0，结果不匹配可能")
    #             return
    #         self.update_stats_display()
    #         self.parse_web_server_log()
    #         self.update_dashboard_stats()
    #
    #         if ai_analysis_starts:  # AI分析记录全部的请求路径
    #             ai_analysis_starts["request"]['log'] = [uri for uri in self.url_stats]
    #             self.ai_analysis_preparation(ai_analysis_starts)  # 开始AI分析
    #         self.add_recent_activity("LOG分析完成", file_path,
    #                                  f"分析成功完成一共：{sum(stats['count'] for stats in self.url_stats.values())}请求，唯一URI：{len(self.url_stats)}")
    #
    #         self.status_label.setText("LOG分析完成")
    #
    #
    #     except Exception as e:
    #         self.log_table.setItem(0, 0, QTableWidgetItem(f"分析日志时出错: {str(e)}"))

    def parse_web_server_log(self):
        """解析Web服务器日志并填充表格"""

        try:

            # 填充表格
            self.log_table.setRowCount(len(self.url_stats))

            sorted_stats = sorted(
                self.url_stats.items(),
                key=lambda item: item[1]['count'],
                reverse=True
            )

            for row, (url, stats) in enumerate(sorted_stats):
                url = unquote(url)
                self.log_table.setItem(row, 0, QTableWidgetItem(url))

                self.log_table.setItem(row, 1, QTableWidgetItem(str(stats.get('count', 0))))

                # 格式化状态码
                status_text = "\n".join(f"{k}:次数{v}" for k, v in stats.get('status_codes', {}).items())
                self.log_table.setItem(row, 2, QTableWidgetItem(status_text))

                # 格式化来源IP
                ip_text = "\n".join(f"{k}:次数{v}\n" for k, v in stats.get('source_ips', {}).items())
                self.log_table.setItem(row, 3, QTableWidgetItem(ip_text))
                self.log_table.setColumnWidth(3, 200)

                # 格式化方法
                method_text = "\n".join(f"{k}:次数{v}" for k, v in stats.get('methods', {}).items())
                self.log_table.setItem(row, 4, QTableWidgetItem(method_text))

                # 格式化方法
                danger_text = "\n".join(f"{k}" for k, v in stats.get('danger', {}).items())
                self.log_table.setItem(row, 5, QTableWidgetItem(danger_text))

                # 格式化UA
                UA = "\n".join(f"{k}:次数{v}" for k, v in stats.get('UA', {}).items())
                self.log_table.setItem(row, 6, QTableWidgetItem(UA))

            self.log_table.setSortingEnabled(True)

            # 调整列宽
            self.log_table.resizeColumnsToContents()
            self.log_table.setColumnWidth(0, 300)  # URL列宽一些

        except Exception as e:
            self.log_table.setRowCount(1)
            self.log_table.setItem(0, 0, QTableWidgetItem(f"解析日志时出错: {str(e)}"))

    def export_log_table(self):
        """导出日志表格为CSV"""
        if self.log_table.rowCount() == 0:
            QMessageBox.warning(self, "警告", "没有可导出的数据!")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存CSV文件",
            f"log_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV文件 (*.csv);;所有文件 (*)"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # 写入表头
                headers = []
                for col in range(self.log_table.columnCount()):
                    headers.append(self.log_table.horizontalHeaderItem(col).text())
                writer.writerow(headers)

                # 写入数据
                for row in range(self.log_table.rowCount()):
                    row_data = []
                    for col in range(self.log_table.columnCount()):
                        item = self.log_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)

            QMessageBox.information(self, "成功", "CSV文件导出成功!")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"导出CSV时出错: {str(e)}")

    def create_status_bar(self):
        """创建状态栏"""
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)

        # 添加状态标签
        self.status_label = QLabel("就绪")
        status_bar.addWidget(self.status_label, stretch=1)

        # 添加版本信息
        version_label = QLabel("TrafficEye Web v" + version)
        status_bar.addPermanentWidget(version_label)

        # 添加系统时间
        self.time_label = QLabel()
        self.update_time()
        status_bar.addPermanentWidget(self.time_label)

        # 创建定时器更新时间
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)

    def update_time(self):
        """更新时间显示"""
        # current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") # 添加显示时间
        current_time = ""
        self.time_label.setText(current_time)

    def show_about_dialog(self):
        """显示关于对话框"""
        about_box = QMessageBox(self)
        about_box.setWindowTitle("关于 TrafficEye Wbe")
        about_box.setIconPixmap(QIcon("ico/l.png").pixmap(64, 64))
        about_box.setText("""
            <h2>TrafficEye</h2>
            <p>版本: 0.0.1</p>
            <p>网络流量分析工具</p>
            <p><a href="https://github.com/CuriousLearnerDev/TrafficEye">访问我们的网站</a></p>
        """)
        about_box.exec()

    def open_documentation(self):
        """打开文档"""
        webbrowser.open("https://github.com/CuriousLearnerDev/TrafficEye")

    def select_file(self):
        """选择流量文件"""
        file, _ = QFileDialog.getOpenFileName(
            self,
            "选择流量文件",
            "",
            "PCAP Files (*.pcap *.pcapng *.cap *.log *.txt);;All Files (*)"
        )
        if file:
            self.Import_box.setText(file)
            self.status_label.setText(f"已选择文件: {file}")
            self.add_recent_activity("打开文件", file, "打开文件")

    def load_recent_activity(self):
        """ 读取之前的操作 """
        path = "history/trafficeye_data.json"
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        recent = data.get("recent", [])
        self.recent_table.setRowCount(len(recent))
        for row, entry in enumerate(recent):
            for col, text in enumerate(entry):
                self.recent_table.setItem(row, col, QTableWidgetItem(text))



    def add_recent_activity(self, action, filename, status, status_color: QColor = None):
        """添加最近活动记录，并可选指定状态颜色"""
        row = self.recent_table.rowCount()
        self.recent_table.insertRow(row)

        time_item = QTableWidgetItem(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        action_item = QTableWidgetItem(action)
        file_item = QTableWidgetItem(filename)
        status_item = QTableWidgetItem(status)

        time_item, action_item, file_item, status_item = session_utils.operational_record_keeping(
            time_item=time_item,
            action_item=action_item,
            file_item=file_item,
            status_item=status_item
        )



        # 如果调用者传了颜色，就用传入的，否则根据内容判断
        if status_color is None:
            status_lower = status.lower()
            if "成功" in status_lower:
                status_color = QColor("#86efac")  # 柔和绿色
            elif "运行中" in status_lower or "分析中" in status_lower or "进行中" in status_lower:
                status_color = QColor("#fde68a")  # 柔和黄色
            elif "失败" in status_lower:
                status_color = QColor("#fca5a5")  # 柔和红色
            else:
                status_color = QColor("#e5e7eb")  # 柔和灰白（避免纯白太亮）

        status_item.setForeground(status_color)

        self.recent_table.setItem(row, 0, time_item)
        self.recent_table.setItem(row, 1, action_item)
        self.recent_table.setItem(row, 2, file_item)
        self.recent_table.setItem(row, 3, status_item)

        self.recent_table.scrollToBottom()

    def get_proxy_settings(self):
        """获取代理设置"""
        if not self.proxy_group.isChecked():
            return None

        proxies = {}
        http_proxy = self.http_proxy_input.text().strip()
        https_proxy = self.https_proxy_input.text().strip()

        if http_proxy:
            proxies['http'] = http_proxy
        if https_proxy:
            proxies['https'] = https_proxy

        return proxies if proxies else None

    # 应用到耗时方法

    def start_analysis(self, ai_analysis_starts=None):
        """开始流量分析"""
        # 清除之前的结果
        self.analysis_text_edit.clear()
        self.memory_optimization=False # 当值变成了真会叫数据写入到硬盘里面
        self.status_create_analysis_tab.setText("")

        # self.progress_bar.setValue(0)

        file = self.Import_box.text()
        if not file:
            QMessageBox.warning(self, "警告", "请先选择流量文件!")
            return
        base_name = os.path.basename(file)  # 取文件名，比如 gsl.cap
        folder_name = os.path.splitext(base_name)[0]  # 去掉扩展名，比如 gsl
        self.start_analysis_timestamp = folder_name+"_"+datetime.datetime.now().strftime("%Y%m%d_%H%M%S")+".txt"

        uri = self.uri_input.text()
        keyword = self.search_input.text()
        request_only = self.request_only_checkbox.isChecked()
        response_only = self.response_only_checkbox.isChecked()
        show_body = self.body_checkbox.isChecked()

        # 禁用按钮，防止重复点击
        self.start_analysis_button.setEnabled(False)
        self.stop_analysis_button.setEnabled(True)


        self.status_label.setText("分析进行中...")

        # 启动分析线程
        self.analysis_thread = AnalysisThread(file, uri, keyword, "", request_only, response_only, show_body,
                                              sslkeylogfile=self.ssl_keylog_input.text(),
                                              ai_analysis_starts=ai_analysis_starts)
        self.analysis_thread.analysis_similar = "pyshark" if self.flow_pyshark_radio.isChecked() else "tshark"

        self.analysis_thread.result_signal.connect(self.update_results)
        self.analysis_thread.progress_signal.connect(self.update_progress)
        self.analysis_thread.finished_signal.connect(self.analysis_finished)
        self.analysis_thread.start()

        self.add_recent_activity("开始分析", file, "进行中")

    def update_progress(self, value):
        """更新进度条"""
        self.progress_bar.setValue(value)

    def stop_analysis(self):
        """停止分析"""
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_thread.terminate()
            self.analysis_thread.wait()
            self.analysis_text_edit.append("\n分析已停止!")
            self.status_label.setText("分析已停止")
            self.add_recent_activity("停止分析", self.Import_box.text(), "已停止")

        self.start_analysis_button.setEnabled(True)
        self.stop_analysis_button.setEnabled(False)

    def clear_results(self):
        """清除分析结果"""
        self.analysis_text_edit.clear()
        # self.progress_bar.setValue(0)
        self.status_label.setText("结果已清除")

    def export_results(self):
        """导出分析结果"""
        if not self.analysis_text_edit.toPlainText():
            QMessageBox.warning(self, "警告", "没有可导出的结果!")
            return

        # 生成默认文件名
        default_name = "analysis_result_"
        if self.Import_box.text():
            import os
            base_name = os.path.splitext(os.path.basename(self.Import_box.text()))[0]
            default_name = f"{base_name}_analysis_"
        default_name += datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出分析结果",
            default_name,
            "Text Files (*.txt);;All Files (*)"
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.analysis_text_edit.toPlainText())
                self.status_label.setText(f"结果已成功导出到: {file_path}")
                self.add_recent_activity("导出结果", file_path, "成功")
                QMessageBox.information(self, "成功", "结果已成功导出!")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
                self.add_recent_activity("导出结果", file_path, f"失败: {str(e)}")

    def memory_optimization_invoke(self,textedit,status_create,text=None, max_lines=5000, auto_save=True):

        # 检查当前行数
        line_count = textedit.document().blockCount()

        if self.memory_optimization:
            module.Searchresults(text, self.start_analysis_timestamp)

        if line_count >= max_lines and auto_save:
            if self.memory_optimization==False: # 保持前5000行内容
                #self.add_recent_activity("警告", self.Import_box.text(), f"[提示] 输出已超过{max_lines}行，完整内容保存到: {self.start_analysis_timestamp}")
                # 获取清空前的数据
                status_create.setText(f"[提示] 输出已超过{max_lines}行，完整内容保存到: {self.start_analysis_timestamp}")
                full_content = textedit.toPlainText()
                module.Searchresults(full_content,self.start_analysis_timestamp)
            textedit.clear() # 清空列表内容
            self.memory_optimization=True # 启动内存优化


    def update_results(self, text):
        self.analysis_text_edit.append(text)
        self.memory_optimization_invoke(self.analysis_text_edit,self.status_create_analysis_tab,text=text)

    # 在AnalysisThread类的analysis_finished方法中添加自动分析逻辑
    def analysis_finished(self, ai_analysis_storing_data=None):
        """分析完成"""
        self.start_analysis_button.setEnabled(True)
        self.stop_analysis_button.setEnabled(False)
        self.analysis_text_edit.append("分析完成！")
        self.status_label.setText("分析完成")
        # 更新统计信息
        if hasattr(self.analysis_thread, 'last_result'):
            self.url_stats = self.analysis_thread.last_result
            self.add_recent_activity("分析完成", self.Import_box.text(),
                                     f"分析成功完成一共：{sum(stats['count'] for stats in self.url_stats.values())}请求，唯一URI：{len(self.url_stats)}")
            self.update_stats_display()
            self.update_dashboard_stats()
        else:
            self.add_recent_activity("分析完成", self.Import_box.text(),
                                     f"分析成功完成一共：{sum(stats['count'] for stats in self.url_stats.values())}请求，唯一URI：{len(self.url_stats)}")

        # 检查是否需要启动AI分析
        if ai_analysis_storing_data:
            self.ai_analysis_preparation(ai_analysis_storing_data)  # 开始AI分析
        # # 自动调用AI分析
        # if hasattr(self.main_window, 'ai_tab') and self.main_window.ai_tab.should_auto_analyze():
        #     self.main_window.ai_tab.start_ai_analysis()

    def update_stats_display(self):
        """更新统计信息显示"""
        # 更新URL表格
        if self.url_stats is None:
            self.url_stats = {}  # 初始化为一个空字典
        self.url_table.setRowCount(len(self.url_stats))

        # 启用滚动
        self.url_table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self.url_table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)

        sorted_stats = sorted(
            self.url_stats.items(),
            key=lambda item: item[1]['count'],
            reverse=True
        )
        for row, (url, stats) in enumerate(sorted_stats):
            self.url_table.setItem(row, 0, QTableWidgetItem(url))
            self.url_table.setItem(row, 1, QTableWidgetItem(str(stats.get('count', 0))))

            # 格式化状态码
            status_text = "\n".join(f"{k}:次数{v}" for k, v in stats.get('status_codes', {}).items())
            self.url_table.setItem(row, 2, QTableWidgetItem(status_text))

            # 格式化来源IP
            ip_text = "\n".join(f"{k}:次数{v}\n" for k, v in stats.get('source_ips', {}).items())
            self.url_table.setItem(row, 3, QTableWidgetItem(ip_text))
            self.url_table.setColumnWidth(3, 200)

            # 格式化方法
            method_text = "\n".join(f"{k}:次数{v}" for k, v in stats.get('methods', {}).items())
            self.url_table.setItem(row, 4, QTableWidgetItem(method_text))

            # 格式化UA
            UA = "\n".join(f"{k}:次数{v}" for k, v in stats.get('UA', {}).items())
            print(UA)
            self.url_table.setItem(row, 5, QTableWidgetItem(UA))
        self.url_table.setSortingEnabled(True)

        # 更新状态码饼图
        status_counts = defaultdict(int)
        for stats in self.url_stats.values():
            for code, count in stats['status_codes'].items():
                status_counts[code] += count

        status_series = QPieSeries()
        status_series.hovered.connect(self.on_pie_hover)  # 连接悬停信号
        for code, count in status_counts.items():
            slice = status_series.append(f"HTTP {code}", count)
            slice.setLabel(f"HTTP {code}: {count}次")

        status_chart = QChart()
        status_chart.addSeries(status_series)
        status_chart.setTitle("状态码分布")
        status_chart.legend().setVisible(True)
        self.status_chart_view.setChart(status_chart)

        # 更新IP统计柱状图
        ip_counts = defaultdict(int)
        for stats in self.url_stats.values():
            for ip, count in stats['source_ips'].items():
                ip_counts[ip] += count

        ip_series = QBarSeries()
        ip_series.setLabelsVisible(True)
        ip_series.hovered.connect(self.on_ip_bar_hover)

        ip_set = QBarSet("请求次数")
        self.ip_categories = []

        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:30]:
            ip_set.append(count)
            self.ip_categories.append(ip)

        ip_series.append(ip_set)
        ip_chart = QChart()
        ip_chart.addSeries(ip_series)
        ip_chart.setTitle("来源IP统计 (Top 30)")

        axis_x = QBarCategoryAxis()
        axis_x.append(self.ip_categories)
        ip_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        ip_series.attachAxis(axis_x)

        axis_y = QValueAxis()
        ip_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        ip_series.attachAxis(axis_y)

        self.ip_chart_view.setChart(ip_chart)

        # 更新URL访问统计柱状图（Top 10）
        url_counts = defaultdict(int)
        for url, stats in self.url_stats.items():
            url_counts[urlparse(url).path] += stats['count']

        url_series = QBarSeries()
        url_series.setLabelsVisible(True)
        url_series.hovered.connect(self.on_url_bar_hover)

        url_set = QBarSet("访问次数")
        self.url_categories = []

        for url, count in sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:30]:
            url_set.append(count)
            self.url_categories.append(url[:30] + "..." if len(url) > 30 else url)  # 缩短长URL

        url_series.append(url_set)
        url_chart = QChart()
        url_chart.addSeries(url_series)
        url_chart.setTitle("URL访问统计(Top 30)")

        url_axis_x = QBarCategoryAxis()
        url_axis_x.append(self.url_categories)
        url_chart.addAxis(url_axis_x, Qt.AlignmentFlag.AlignBottom)
        url_series.attachAxis(url_axis_x)

        url_axis_y = QValueAxis()
        url_chart.addAxis(url_axis_y, Qt.AlignmentFlag.AlignLeft)
        url_series.attachAxis(url_axis_y)

        self.uri_chart_view.setChart(url_chart)

        # 更新访问时间趋势图（按分钟统计）
        time_buckets = defaultdict(int)
        for stats in self.url_stats.values():
            for timestamp in stats.get('request_time', []):
                dt = datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                minute_precision = dt.strftime('%Y-%m-%d %H:%M:%S')
                time_buckets[minute_precision] += 1

        sorted_times = sorted(time_buckets.items())  # 按时间排序

        time_series = QLineSeries()
        time_series.setPointsVisible(True)
        time_series.hovered.connect(self.on_time_hover)
        self.time_data = []  # 存储时间点数据用于悬停显示

        for i, (time_str, count) in enumerate(sorted_times):
            time_series.append(i, count)
            self.time_data.append((time_str, count))

        time_chart = QChart()
        time_chart.addSeries(time_series)
        time_chart.setTitle("访问时间趋势图（分）")

        # 减少X轴标签数量，避免重叠
        time_axis_x = QCategoryAxis()
        step = max(1, len(sorted_times) // 10)  # 最多显示10个标签
        for i, (time_str, _) in enumerate(sorted_times):
            if i % step == 0 or i == len(sorted_times) - 1:
                time_axis_x.append(time_str.split()[1][:5], i)  # 只显示时间部分
        time_chart.addAxis(time_axis_x, Qt.AlignmentFlag.AlignBottom)
        time_series.attachAxis(time_axis_x)

        time_axis_y = QValueAxis()
        time_chart.addAxis(time_axis_y, Qt.AlignmentFlag.AlignLeft)
        time_series.attachAxis(time_axis_y)

        self.time_chart_view.setChart(time_chart)

    def on_pie_hover(self, slice, state):
        """处理饼图悬停事件"""
        if state:
            # 显示更详细的信息
            QToolTip.showText(
                QCursor.pos(),
                f"{slice.label()}\n占比: {slice.percentage() * 100:.1f}%",
                self.status_chart_view
            )
        else:
            QToolTip.hideText()

    def on_ip_bar_hover(self, status, index, barset):
        """处理IP柱状图悬停事件"""
        if status:
            ip = self.ip_categories[index]
            value = barset.at(index)

            # 获取图表位置
            chart = self.ip_chart_view.chart()
            pos_in_chart = self.ip_chart_view.mapFromGlobal(QCursor.pos())
            scene_pos = self.ip_chart_view.mapToScene(pos_in_chart)
            chart_pos = chart.mapFromScene(scene_pos)

            # 计算工具提示位置
            tooltip_pos = self.ip_chart_view.mapToGlobal(
                self.ip_chart_view.mapFromScene(chart.mapToScene(chart_pos))
            )

            QToolTip.showText(
                tooltip_pos,
                f"IP: {ip}\n请求次数: {int(value)}",
                self.ip_chart_view
            )
        else:
            QToolTip.hideText()

    def on_url_bar_hover(self, status, index, barset):
        """处理URL柱状图悬停事件"""
        if status:
            url = self.url_categories[index]
            value = barset.at(index)

            # 获取完整URL（如果有被截断）
            full_url = self.url_categories[index] if len(self.url_categories[index]) <= 33 else \
                [k for k in self.url_stats.keys() if
                 urlparse(k).path.startswith(self.url_categories[index].split("...")[0])][0]

            chart = self.uri_chart_view.chart()
            pos_in_chart = self.uri_chart_view.mapFromGlobal(QCursor.pos())
            scene_pos = self.uri_chart_view.mapToScene(pos_in_chart)
            chart_pos = chart.mapFromScene(scene_pos)

            tooltip_pos = self.uri_chart_view.mapToGlobal(
                self.uri_chart_view.mapFromScene(chart.mapToScene(chart_pos))
            )

            QToolTip.showText(
                tooltip_pos,
                f"URL: {full_url}\n访问次数: {int(value)}",
                self.uri_chart_view
            )
        else:
            QToolTip.hideText()

    def on_time_hover(self, point, state):
        """处理时间趋势图悬停事件"""
        if state:
            index = int(point.x())
            if 0 <= index < len(self.time_data):
                time_str, count = self.time_data[index]
                QToolTip.showText(
                    QCursor.pos(),
                    f"时间: {time_str}\n访问量: {int(count)}",
                    self.time_chart_view
                )
        else:
            QToolTip.hideText()
    # def update_stats_display(self):
    #     """更新统计信息显示"""
    #     # 更新URL表格
    #     if self.url_stats is None:
    #         self.url_stats = {}  # 初始化为一个空字典
    #     self.url_table.setRowCount(len(self.url_stats))
    #
    #     # 启用滚动
    #     self.url_table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
    #     self.url_table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
    #
    #
    #     sorted_stats = sorted(
    #         self.url_stats.items(),
    #         key=lambda item: item[1]['count'],
    #         reverse=True
    #     )
    #     for row, (url, stats) in enumerate(sorted_stats):
    #         self.url_table.setItem(row, 0, QTableWidgetItem(url))
    #         self.url_table.setItem(row, 1, QTableWidgetItem(str(stats.get('count', 0))))
    #
    #         # 格式化状态码
    #         status_text = "\n".join(f"{k}:次数{v}" for k, v in stats.get('status_codes', {}).items())
    #         self.url_table.setItem(row, 2, QTableWidgetItem(status_text))
    #
    #         # 格式化来源IP
    #         ip_text = "\n".join(f"{k}:次数{v}\n" for k, v in stats.get('source_ips', {}).items())
    #         self.url_table.setItem(row, 3, QTableWidgetItem(ip_text))
    #         self.url_table.setColumnWidth(3, 200)
    #
    #         # 格式化方法
    #         method_text = "\n".join(f"{k}:次数{v}" for k, v in stats.get('methods', {}).items())
    #         self.url_table.setItem(row, 4, QTableWidgetItem(method_text))
    #
    #         # 格式化UA
    #         UA = "\n".join(f"{k}:次数{v}" for k, v in stats.get('UA', {}).items())
    #         print(UA)
    #         self.url_table.setItem(row, 5, QTableWidgetItem(UA))
    #     self.url_table.setSortingEnabled(True)
    #
    #     # 更新状态码饼图
    #     status_counts = defaultdict(int)
    #     for stats in self.url_stats.values():
    #         for code, count in stats['status_codes'].items():
    #             status_counts[code] += count
    #
    #     status_series = QPieSeries()
    #     for code, count in status_counts.items():
    #         status_series.append(f"HTTP {code}", count)
    #
    #     status_chart = QChart()
    #     status_chart.addSeries(status_series)
    #     status_chart.setTitle("状态码分布")
    #     self.status_chart_view.setChart(status_chart)
    #
    #     # 更新IP统计柱状图
    #     ip_counts = defaultdict(int)
    #     for stats in self.url_stats.values():
    #         for ip, count in stats['source_ips'].items():
    #             ip_counts[ip] += count
    #
    #     ip_series = QBarSeries()
    #     ip_series.setLabelsVisible(True)
    #     ip_series.hovered.connect(self.on_bar_hover)
    #
    #
    #     ip_set = QBarSet("请求次数")
    #     self.categories = []
    #
    #     for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
    #         ip_set.append(count)
    #         self.categories.append(ip)
    #
    #     ip_series.append(ip_set)
    #     ip_chart = QChart()
    #     ip_chart.addSeries(ip_series)
    #     ip_chart.setTitle("来源IP统计 (Top 15)")
    #
    #     axis_x = QBarCategoryAxis()
    #     axis_x.append(self.categories)
    #     ip_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
    #     ip_series.attachAxis(axis_x)
    #
    #     axis_y = QValueAxis()
    #     ip_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
    #     ip_series.attachAxis(axis_y)
    #
    #     self.ip_chart_view.setChart(ip_chart)
    #
    #     # 更新URL访问统计柱状图（Top 10）
    #     url_counts = defaultdict(int)
    #     for url, stats in self.url_stats.items():
    #         url_counts[urlparse(url).path] += stats['count']
    #
    #     url_series = QBarSeries()
    #     url_set = QBarSet("访问次数")
    #     url_categories = []
    #
    #     for url, count in sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
    #         url_set.append(count)
    #         url_categories.append(url)
    #
    #     url_series.append(url_set)
    #     url_chart = QChart()
    #     url_chart.addSeries(url_series)
    #     url_chart.setTitle("URL访问统计 (Top 10)")
    #
    #     url_axis_x = QBarCategoryAxis()
    #     url_axis_x.append(url_categories)
    #     url_chart.addAxis(url_axis_x, Qt.AlignmentFlag.AlignBottom)
    #     url_series.attachAxis(url_axis_x)
    #
    #     url_axis_y = QValueAxis()
    #     url_chart.addAxis(url_axis_y, Qt.AlignmentFlag.AlignLeft)
    #     url_series.attachAxis(url_axis_y)
    #
    #     self.uri_chart_view.setChart(url_chart)
    #
    #     # 更新访问时间趋势图（按小时统计）
    #     time_buckets = defaultdict(int)
    #     for stats in self.url_stats.values():
    #         for timestamp in stats.get('request_time', []):  # 假设你有 'timestamps': [datetime, datetime, ...]
    #             dt = datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
    #             minute_precision = dt.strftime('%Y-%m-%d %H:%M:%S')
    #             time_buckets[minute_precision] += 1
    #
    #     sorted_times = sorted(time_buckets.items())  # 按时间排序
    #     print(sorted_times)
    #
    #     time_series = QLineSeries()
    #     for i, (time_str, count) in enumerate(sorted_times):
    #         time_series.append(i, count)
    #
    #     time_chart = QChart()
    #     time_chart.addSeries(time_series)
    #     time_chart.setTitle("访问时间趋势图（分）")
    #
    #     time_axis_x = QCategoryAxis()
    #     for i, (time_str, _) in enumerate(sorted_times):
    #
    #         time_axis_x.append(time_str, i)
    #     time_chart.addAxis(time_axis_x, Qt.AlignmentFlag.AlignBottom)
    #     time_series.attachAxis(time_axis_x)
    #
    #     time_axis_y = QValueAxis()
    #     time_chart.addAxis(time_axis_y, Qt.AlignmentFlag.AlignLeft)
    #     time_series.attachAxis(time_axis_y)
    #
    #     self.time_chart_view.setChart(time_chart)



    # def on_bar_hover(self, status, index, barset):
    #     """处理柱状图悬停事件"""
    #     if status:  # 鼠标进入柱状图
    #         month = self.categories[index]
    #         value = barset.at(index)
    #
    #         # 获取柱状图的位置
    #         chart = self.ip_chart_view.chart()
    #         pos_in_chart = self.ip_chart_view.mapFromGlobal(self.cursor().pos())
    #         scene_pos = self.ip_chart_view.mapToScene(pos_in_chart)
    #         chart_pos = chart.mapFromScene(scene_pos)
    #
    #         # 计算工具提示位置
    #         tooltip_pos = self.ip_chart_view.mapToGlobal( self.ip_chart_view.mapFromScene(chart.mapToScene(chart_pos)))
    #
    #         # 显示工具提示
    #         QToolTip.showText(
    #             tooltip_pos,
    #             f"{month}\nIP: {int(value)}次数",
    #             self.ip_chart_view
    #         )
    #     else:  # 鼠标离开柱状图
    #         QToolTip.hideText()

    def ai_analysis_preparation(self, ai_analysis_storing_data):
        """ 准备分析AI分析工作 """
        if not ai_analysis_storing_data:
            QMessageBox.warning(self, "警告", "没有可用的分析数据!")
            return

        # # 根据选择的模型启动分析线程
        model_type = self.ai_model_combo.currentText()
        # print(model_type)

        # 准备分析数据
        traffic_type, analysis_data = ai_analysis_core.prepare_ai_analysis_data(ai_analysis_storing_data,
                                                                                analysis_selection=self.analysis_selection)

        self.analysis_thread = AIAnalysisThread(
            model_type=model_type,
            analysis_data=analysis_data,
            config=self.config,
            traffic_type=traffic_type  # 流量类型
        )

        self.analysis_thread.result_signal.connect(self.update_ai_result)
        self.analysis_thread.update_content.connect(self.update_ai_content)
        self.analysis_thread.finished_signal.connect(self.ai_analysis_finished)
        self.analysis_thread.start()
        self.status_label.setText("开始AI分析中请稍等...")
        self.add_recent_activity("AI分析", self.Import_box.text(), "AI分析分析中.....")

    def extract_url_params(self, url):
        """从URL中提取参数"""
        try:
            parsed = urlparse(url)
            params = {}

            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value

            return params
        except:
            return {}

    def update_ai_result(self, text):
        """更新AI分析结果"""
        self.ai_result_text.moveCursor(QTextCursor.MoveOperation.End)
        self.ai_result_text.insertPlainText(text)
        self.ai_result_text.moveCursor(QTextCursor.MoveOperation.End)

    def update_ai_content(self, text):
        """更新AI分析结果"""
        self.ai_analysis_result_text.moveCursor(QTextCursor.MoveOperation.End)
        self.ai_analysis_result_text.insertPlainText(text)
        self.ai_analysis_result_text.moveCursor(QTextCursor.MoveOperation.End)

    def ai_analysis_finished(self, ErrorResponse=""):
        """AI分析完成"""
        self.ai_analyze_btn.setEnabled(True)
        self.ai_stop_btn.setEnabled(False)
        self.status_label.setText(ErrorResponse)
        self.ai_result_text.append(ErrorResponse)
        self.add_recent_activity("AI分析", self.Import_box.text(), ErrorResponse)

    def stop_ai_analysis(self):
        """停止AI分析"""
        if self.ai_analysis_thread and self.ai_analysis_thread.isRunning():
            self.ai_analysis_thread.terminate()
            self.ai_analysis_thread.wait()

        self.ai_analyze_btn.setEnabled(True)
        self.ai_stop_btn.setEnabled(False)
        self.status_label.setText("AI分析已停止")

    def select_save_path(self):
        """选择保存路径"""
        path = QFileDialog.getExistingDirectory(
            self,
            "选择保存目录"
        )
        if path:
            self.save_path_input.setText(path)
            self.add_recent_activity("设置保存路径", path, "成功")

    def extraction_finished(self):
        """提取完成"""
        self.extract_btn.setEnabled(True)
        self.stop_extract_btn.setEnabled(False)
        self.status_label.setText("HTTP文件提取完成")
        self.add_recent_activity("HTTP文件提取", self.Import_box.text(), "完成")

    def stop_extraction(self):
        """停止提取"""
        if hasattr(self, 'extract_thread') and self.extract_thread.isRunning():
            self.extract_thread.terminate()
            self.extract_thread.wait()

        self.extract_btn.setEnabled(True)
        self.stop_extract_btn.setEnabled(False)
        self.status_label.setText("提取已停止")
        self.add_recent_activity("停止提取", self.Import_box.text(), "已停止")

    def clear_extract_results(self):
        """清除提取结果"""
        self.file_table.setRowCount(0)
        self.status_label.setText("结果已清除")

    def open_saved_file(self, index):
        """打开已保存的文件"""
        row = index.row()
        save_path = self.file_table.item(row, 5).text()

        if not save_path or not os.path.exists(save_path):
            QMessageBox.warning(self, "警告", "文件不存在或未保存!")
            return

        try:
            if sys.platform == "win32":
                os.startfile(save_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", save_path])
            else:
                subprocess.run(["xdg-open", save_path])
        except Exception as e:
            QMessageBox.warning(self, "错误", f"无法打开文件: {str(e)}")

    def save_selected_files(self):
        """保存选中文件"""
        selected = self.file_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "警告", "请先选择要保存的文件!")
            return

        # 获取保存路径
        save_path = self.save_path_input.text()
        if not save_path:
            save_path = QFileDialog.getExistingDirectory(self, "选择保存目录")
            if not save_path:
                return
            self.save_path_input.setText(save_path)

        # 获取选中的行
        rows = set(item.row() for item in selected)
        saved_count = 0

        # 这里应该实现实际的文件保存逻辑
        for row in rows:
            # 模拟保存文件
            self.file_table.item(row, 4).setText("已保存")
            self.file_table.item(row, 5).setText(os.path.join(save_path, self.file_table.item(row, 0).text()))
            saved_count += 1

        QMessageBox.information(self, "成功", f"已保存 {saved_count} 个文件到 {save_path}")
        self.add_recent_activity("保存选中文件", f"{saved_count}个文件", "成功")

    def save_all_files(self):
        """保存所有文件"""
        if self.file_table.rowCount() == 0:
            QMessageBox.warning(self, "警告", "没有可保存的文件!")
            return

        # 获取保存路径
        save_path = self.save_path_input.text()
        if not save_path:
            save_path = QFileDialog.getExistingDirectory(self, "选择保存目录")
            if not save_path:
                return
            self.save_path_input.setText(save_path)

        saved_count = 0

        # 这里应该实现实际的文件保存逻辑
        for row in range(self.file_table.rowCount()):
            # 模拟保存文件
            self.file_table.item(row, 4).setText("已保存")
            self.file_table.item(row, 5).setText(os.path.join(save_path, self.file_table.item(row, 0).text()))
            saved_count += 1

        QMessageBox.information(self, "成功", f"已保存 {saved_count} 个文件到 {save_path}")
        self.add_recent_activity("保存所有文件", f"{saved_count}个文件", "成功")

    def export_file_list(self):
        """导出文件列表"""
        if self.file_table.rowCount() == 0:
            QMessageBox.warning(self, "警告", "没有可导出的文件列表!")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出文件列表",
            "http_extracted_files.csv",
            "CSV Files (*.csv);;All Files (*)"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # 写入表头
                headers = []
                for col in range(self.file_table.columnCount()):
                    headers.append(self.file_table.horizontalHeaderItem(col).text())
                writer.writerow(headers)

                # 写入数据
                for row in range(self.file_table.rowCount()):
                    row_data = []
                    for col in range(self.file_table.columnCount()):
                        item = self.file_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)

            QMessageBox.information(self, "成功", "文件列表导出成功!")
            self.add_recent_activity("导出文件列表", file_path, "成功")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"导出失败: {str(e)}")
            self.add_recent_activity("导出文件列表", file_path, f"失败: {str(e)}")

    def start_http_extraction(self):
        """开始提取HTTP文件"""
        file = self.Import_box.text()
        if not file:
            QMessageBox.warning(self, "警告", "请先选择流量文件!")
            return

        save_path = self.save_path_input.text()
        if not save_path:
            QMessageBox.warning(self, "警告", "请选择保存目录!")
            return

        # 获取选中的文件类型
        selected_index = self.file_filter_combo.currentIndex()
        file_filter = ["java_class", "java_serialized"]

        # 如果不是"所有文件类型"，则获取具体的文件类型
        if selected_index > 0:
            selected_text = self.file_filter_combo.currentText()
            if selected_text.split()[0] == "所有文件类型":
                file_filter = None
            else:
                # 从"类型 文件"格式中提取类型
                file_filter = [selected_text.split()[0]]

        # 清空之前的结果
        self.file_table.setRowCount(0)

        # 更新UI状态
        self.extract_btn.setEnabled(False)
        self.stop_extract_btn.setEnabled(True)

        # 获取SSL密钥日志文件路径（如果有）
        ssl_keylog = self.ssl_keylog_input.text() if self.ssl_keylog_input.text() else None

        fileextraction = {
            "file_filter": file_filter,  # 是否是要是选择的文件类型
            "save_path": save_path  # 提取要保存的文件
        }

        # 创建并启动提取线程
        self.extract_thread = AnalysisThread(
            file=file,
            uri="",
            keyword="",
            output="",
            request_only=True,
            response_only=False,
            show_body=True,
            sslkeylogfile=ssl_keylog,
            fileextraction=fileextraction
        )
        self.extract_thread.analysis_similar = "pyshark" if self.extract_pyshark_radio.isChecked() else "tshark"
        self.extract_thread.result_signal_extract.connect(self.add_extracted_file)
        self.extract_thread.finished_signal.connect(self.extraction_finished)
        self.extract_thread.status_label.connect(self.update_status_label)
        self.extract_thread.start()

        self.status_label.setText("正在提取HTTP文件...")
        self.add_recent_activity("开始提取HTTP文件", file, "进行中")

    def add_extracted_file(self, file_info: dict):
        """添加提取的文件到表格"""

        row = self.file_table.rowCount()
        self.file_table.insertRow(row)

        # 提取需要展示的字段
        display_fields = [
            file_info.get("filename", "N/A"),
            file_info.get("filetype", "N/A"),
            f"{file_info.get('size', 0)} B",
            file_info.get("url", "N/A"),
            file_info.get("status", "N/A"),
            file_info.get("save_path", "N/A"),
        ]

        for col, text in enumerate(display_fields):
            item = QTableWidgetItem(str(text))
            self.file_table.setItem(row, col, item)

    def select_ssl_keylog_file(self):
        """选择SSL密钥日志文件"""
        file, _ = QFileDialog.getOpenFileName(
            self,
            "选择SSL密钥日志文件",
            "",
            "Keylog Files (*.log *.keylog);;All Files (*)"
        )
        if file:
            self.ssl_keylog_input.setText(file)
            self.add_recent_activity("选择SSL密钥文件", file, "成功")

    #
    # def create_extract_tab(self):
    #     """创建HTTP文件提取选项卡"""
    #     tab = QWidget()
    #     self.workspace.addTab(tab, QIcon("ico/extract.png"), "HTTP文件提取")
    #     self.tabs["extract"] = tab
    #
    #     # 主布局
    #     layout = QVBoxLayout(tab)
    #     layout.setContentsMargins(5, 5, 5, 5)
    #     layout.setSpacing(10)
    #
    #     # 读取config.yaml文件
    #     try:
    #         signatures = self.config.get('signatures', [])
    #
    #         # 收集所有唯一的文件类型
    #         file_types = set()
    #         for sig in signatures:
    #             if sig.get('enabled', False):
    #                 file_type = sig.get('type', '')
    #                 if file_type:
    #                     file_types.add(file_type)
    #
    #         # 转换为排序后的列表
    #         file_types = sorted(file_types)
    #
    #     except Exception as e:
    #         print(f"Error loading config.yaml: {e}")
    #         file_types = []
    #
    #     # SSL密钥日志文件（用于解密HTTPS）
    #     ssl_group = QGroupBox("分析选项")
    #     ssl_layout = QHBoxLayout(ssl_group)
    #     # 分析类型下拉框
    #     self.pyshark_radio = QRadioButton("使用pyshark (Python库)")
    #     self.pyshark_radio.setChecked(True)
    #     self.tshark_radio = QRadioButton("使用tshark")
    #
    #     ssl_layout.addWidget(self.pyshark_radio)
    #     ssl_layout.addWidget(self.tshark_radio)
    #     self.ssl_keylog_input = QLineEdit()
    #     self.ssl_keylog_input.setPlaceholderText("选择SSL密钥日志文件...")
    #
    #     ssl_browse_btn = QPushButton("浏览...")
    #     ssl_browse_btn.clicked.connect(self.select_ssl_keylog_file)
    #
    #     ssl_layout.addWidget(self.ssl_keylog_input)
    #     ssl_layout.addWidget(ssl_browse_btn)
    #
    #
    #     layout.addWidget(ssl_group)
    #
    #     # 提取选项区域
    #     options_group = QGroupBox("HTTP文件提取选项")
    #     options_layout = QGridLayout(options_group)
    #
    #     # 文件类型过滤
    #     self.file_filter_combo = QComboBox()
    #
    #     # 添加默认选项
    #     default_options = ["所有文件类型"]
    #
    #     # 添加从config.yaml中读取的文件类型
    #     if file_types:
    #         self.file_filter_combo.addItems(default_options)
    #         self.file_filter_combo.insertSeparator(len(default_options))
    #
    #         # 添加从配置文件中读取的特定文件类型
    #         for file_type in file_types:
    #             self.file_filter_combo.addItem(f"{file_type} 文件")
    #     else:
    #         # 如果读取配置文件失败，使用默认选项
    #         self.file_filter_combo.addItems(default_options)
    #
    #     # 默认路径：项目目录下的 output 文件夹
    #     default_save_path = os.path.join(os.getcwd(), "output")
    #     os.makedirs(default_save_path, exist_ok=True)  # 如果文件夹不存在则创建
    #
    #
    #     # 保存路径选择
    #     self.save_path_input = QLineEdit()
    #     self.save_path_input.setPlaceholderText("选择保存目录...")
    #
    #     self.save_path_input.setText(default_save_path)  # 设置默认路径
    #     save_path_btn = QPushButton("浏览...")
    #     save_path_btn.clicked.connect(self.select_save_path)
    #
    #     options_layout.addWidget(QLabel("文件类型过滤:"), 0, 0)
    #     options_layout.addWidget(self.file_filter_combo, 0, 1)
    #
    #     options_layout.addWidget(QLabel("保存路径:"), 2, 0)
    #     options_layout.addWidget(self.save_path_input, 2, 1)
    #     options_layout.addWidget(save_path_btn, 2, 2)
    #
    #     layout.addWidget(options_group)
    #
    #     # 其余代码保持不变...
    #     # 提取控制区域
    #     control_group = QGroupBox("提取控制")
    #     control_layout = QHBoxLayout(control_group)
    #
    #     self.extract_btn = QPushButton("开始提取HTTP文件")
    #     self.extract_btn.setIcon(QIcon("ico/extract.png"))
    #     self.extract_btn.clicked.connect(self.start_http_extraction)
    #
    #     self.stop_extract_btn = QPushButton("停止")
    #     self.stop_extract_btn.setIcon(QIcon("ico/stop.png"))
    #     self.stop_extract_btn.setEnabled(False)
    #     self.stop_extract_btn.clicked.connect(self.stop_extraction)
    #
    #     self.clear_extract_btn = QPushButton("清除结果")
    #     self.clear_extract_btn.setIcon(QIcon("ico/clear.png"))
    #     self.clear_extract_btn.clicked.connect(self.clear_extract_results)
    #
    #     control_layout.addWidget(self.extract_btn)
    #     control_layout.addWidget(self.stop_extract_btn)
    #     control_layout.addWidget(self.clear_extract_btn)
    #     layout.addWidget(control_group)
    #
    #     # 结果展示区域
    #     result_group = QGroupBox("HTTP文件提取结果")
    #     result_layout = QVBoxLayout(result_group)
    #
    #     # 文件列表表格
    #     self.file_table = QTableWidget()
    #     self.file_table.setColumnCount(6)
    #     self.file_table.setHorizontalHeaderLabels(["文件名", "类型", "大小", "URL", "状态", "保存路径"])
    #     self.file_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    #     self.file_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    #     self.file_table.horizontalHeader().setStretchLastSection(True)
    #     self.file_table.setSortingEnabled(True)
    #     self.file_table.doubleClicked.connect(self.open_saved_file)
    #
    #     # 设置列宽
    #     self.file_table.setColumnWidth(0, 150)  # 文件名
    #     self.file_table.setColumnWidth(1, 80)  # 类型
    #     self.file_table.setColumnWidth(2, 80)  # 大小
    #     self.file_table.setColumnWidth(3, 300)  # URL
    #     self.file_table.setColumnWidth(4, 80)  # 状态
    #
    #     result_layout.addWidget(self.file_table)
    #     layout.addWidget(result_group)
    #
    #     # 操作按钮区域
    #     action_group = QGroupBox("文件操作")
    #     action_layout = QHBoxLayout(action_group)
    #
    #     self.save_selected_btn = QPushButton("保存选中文件")
    #     self.save_selected_btn.setIcon(QIcon("ico/save.png"))
    #     self.save_selected_btn.clicked.connect(self.save_selected_files)
    #
    #     self.save_all_btn = QPushButton("保存所有文件")
    #     self.save_all_btn.setIcon(QIcon("ico/save_all.png"))
    #     self.save_all_btn.clicked.connect(self.save_all_files)
    #
    #     self.export_list_btn = QPushButton("导出文件列表")
    #     self.export_list_btn.setIcon(QIcon("ico/export.png"))
    #     self.export_list_btn.clicked.connect(self.export_file_list)
    #
    #     action_layout.addWidget(self.save_selected_btn)
    #     action_layout.addWidget(self.save_all_btn)
    #     action_layout.addWidget(self.export_list_btn)
    #     layout.addWidget(action_group)
    def create_extract_tab(self):
        """创建HTTP文件提取选项卡（美化版，PyQt6适配）"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/extract.png"), "HTTP文件提取")
        self.tabs["extract"] = tab

        # 主布局 - 使用垂直布局
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(15)

        # ==================== 第一部分：分析选项 ====================
        analysis_group = QGroupBox("分析选项")
        analysis_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        analysis_layout = QGridLayout(analysis_group)
        analysis_layout.setContentsMargins(10, 15, 10, 15)
        analysis_layout.setSpacing(15)

        # 分析引擎选择
        engine_label = QLabel("分析方式:")
        engine_label.setStyleSheet("font-weight: normal;")
        self.extract_pyshark_radio = QRadioButton("pyshark (Python库)")
        self.extract_pyshark_radio.setStyleSheet("""
            QRadioButton::indicator {

                border: 2px solid #007BFF;
                border-radius: 8px;
                background-color: transparent;
            }
            QRadioButton::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
        """)

        self.tshark_radio = QRadioButton("tshark")
        self.tshark_radio.setChecked(True)
        self.tshark_radio.setStyleSheet("""
            QRadioButton::indicator {

                border: 2px solid #007BFF;
                border-radius: 8px;
                background-color: transparent;
            }
            QRadioButton::indicator:checked {
                background-color: #007BFF;
                border: 2px solid #007BFF;
            }
        """)

        engine_layout = QHBoxLayout()
        engine_layout.addWidget(self.extract_pyshark_radio)
        engine_layout.addWidget(self.tshark_radio)
        engine_layout.addStretch()

        analysis_layout.addWidget(engine_label, 0, 0)
        analysis_layout.addLayout(engine_layout, 0, 1, 1, 2)

        # SSL密钥日志文件
        ssl_label = QLabel("可选参数 SSL密钥日志:")
        ssl_label.setStyleSheet("font-weight: normal;")
        self.ssl_keylog_input = QLineEdit()
        self.ssl_keylog_input.setPlaceholderText("选择SSL密钥日志文件...")
        self.ssl_keylog_input.setStyleSheet("padding: 5px;")

        ssl_browse_btn = QPushButton("浏览...")
        ssl_browse_btn.setStyleSheet("padding: 5px 10px;")
        ssl_browse_btn.clicked.connect(self.select_ssl_keylog_file)

        analysis_layout.addWidget(ssl_label, 1, 0)
        analysis_layout.addWidget(self.ssl_keylog_input, 1, 1)
        analysis_layout.addWidget(ssl_browse_btn, 1, 2)

        main_layout.addWidget(analysis_group)

        # ==================== 第二部分：提取选项 ====================
        extract_group = QGroupBox("提取选项")
        extract_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        extract_layout = QGridLayout(extract_group)
        extract_layout.setContentsMargins(10, 15, 10, 15)
        extract_layout.setSpacing(15)

        # 读取config.yaml文件获取文件类型
        try:
            signatures = self.config.get('signatures', [])
            file_types = sorted(
                {sig.get('type', '') for sig in signatures if sig.get('enabled', False) and sig.get('type', '')})
        except Exception as e:
            print(f"Error loading config.yaml: {e}")
            file_types = []
        # 默认选项
        default_options = ["所有文件类型"]

        # 合并默认选项和文件类型，并确保默认选项在前面
        file_types = default_options + sorted(set(file_types) - set(default_options))

        # 文件类型过滤
        filter_label = QLabel("文件类型:")
        filter_label.setStyleSheet("font-weight: normal;")

        self.file_filter_combo = QComboBox()
        self.file_filter_combo.addItem("识别提取常见序列化二数据")
        if file_types:
            self.file_filter_combo.insertSeparator(1)
            for file_type in file_types:
                self.file_filter_combo.addItem(f"{file_type} 文件")

        # 设置字体和背景色，避免显示问题
        self.file_filter_combo.setStyleSheet("""
            padding: 5px;
            background-color: #3A3A3A;
            color: black;
            font-size: 14px;
            font-family: Arial, sans-serif;
        """)

        extract_layout.addWidget(filter_label, 0, 0)
        extract_layout.addWidget(self.file_filter_combo, 0, 1, 1, 2)

        # 保存路径
        save_label = QLabel("保存路径:")
        save_label.setStyleSheet("font-weight: normal;")
        default_save_path = os.path.join(os.getcwd(), "output")
        os.makedirs(default_save_path, exist_ok=True)

        self.save_path_input = QLineEdit(default_save_path)
        self.save_path_input.setPlaceholderText("选择保存目录...")
        self.save_path_input.setStyleSheet("padding: 5px;")

        save_path_btn = QPushButton("浏览...")
        save_path_btn.setStyleSheet("padding: 5px 10px;")
        save_path_btn.clicked.connect(self.select_save_path)

        extract_layout.addWidget(save_label, 1, 0)
        extract_layout.addWidget(self.save_path_input, 1, 1)
        extract_layout.addWidget(save_path_btn, 1, 2)

        main_layout.addWidget(extract_group)

        # ==================== 第三部分：控制按钮 ====================
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(10)

        # 添加左侧弹簧使按钮居中
        control_layout.addStretch()

        # 开始提取按钮
        self.extract_btn = QPushButton("开始提取")
        self.extract_btn.setIcon(QIcon("ico/extract.png"))
        self.extract_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 160px;

                border: none;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover { background-color: #45a049; }
        """)
        self.extract_btn.clicked.connect(self.start_http_extraction)

        # 停止按钮
        self.stop_extract_btn = QPushButton("停止")
        self.stop_extract_btn.setIcon(QIcon("ico/stop.png"))
        self.stop_extract_btn.setEnabled(False)
        self.stop_extract_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 160px;

                border: none;
                border-radius: 4px;
                min-width: 100px;
            }
        """)
        self.stop_extract_btn.clicked.connect(self.stop_extraction)

        # 清除按钮
        self.clear_extract_btn = QPushButton("清除结果")
        self.clear_extract_btn.setIcon(QIcon("ico/clear.png"))
        self.clear_extract_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 160px;

                border: none;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover { background-color: #0b7dda; }
        """)
        self.clear_extract_btn.clicked.connect(self.clear_extract_results)

        # 添加按钮到布局
        control_layout.addWidget(self.extract_btn)
        control_layout.addWidget(self.stop_extract_btn)
        control_layout.addWidget(self.clear_extract_btn)

        # 添加右侧弹簧使按钮居中
        control_layout.addStretch()

        main_layout.addWidget(control_frame)

        # ==================== 第四部分：结果表格 ====================
        result_group = QGroupBox("提取结果")
        result_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        result_layout = QVBoxLayout(result_group)
        result_layout.setContentsMargins(5, 15, 5, 5)
        result_layout.setSpacing(10)

        # 文件列表表格
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(6)
        self.file_table.setHorizontalHeaderLabels(["文件名", "类型", "大小", "URL", "状态", "保存路径"])
        self.file_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.file_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.file_table.horizontalHeader().setStretchLastSection(True)
        self.file_table.setSortingEnabled(True)
        self.file_table.doubleClicked.connect(self.open_saved_file)

        # 美化表格样式
        self.file_table.setStyleSheet("""

            QHeaderView::section {

                padding: 5px;
                border: none;
            }
        """)

        # 设置列宽和列策略 (PyQt6使用新的枚举值)
        header = self.file_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # 文件名
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # 类型
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # 大小
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # URL
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # 状态
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # 保存路径

        result_layout.addWidget(self.file_table)
        main_layout.addWidget(result_group)

        # ==================== 第五部分：操作按钮 ====================
        action_frame = QFrame()
        action_layout = QHBoxLayout(action_frame)
        action_layout.setContentsMargins(0, 0, 0, 0)
        action_layout.setSpacing(10)

        # 添加左侧弹簧使按钮居中
        action_layout.addStretch()

        # 保存选中按钮
        self.save_selected_btn = QPushButton("保存选中")
        self.save_selected_btn.setIcon(QIcon("ico/save.png"))
        self.save_selected_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 20px;
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover { background-color: #0b7dda; }
        """)
        self.save_selected_btn.clicked.connect(self.save_selected_files)

        # 保存所有按钮
        self.save_all_btn = QPushButton("保存全部")
        self.save_all_btn.setIcon(QIcon("ico/save_all.png"))
        self.save_all_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 20px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover { background-color: #45a049; }
        """)
        self.save_all_btn.clicked.connect(self.save_all_files)

        # 导出列表按钮
        self.export_list_btn = QPushButton("导出列表")
        self.export_list_btn.setIcon(QIcon("ico/export.png"))
        self.export_list_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 20px;
                background-color: #673AB7;
                color: white;
                border: none;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover { background-color: #5e35b1; }
        """)
        self.export_list_btn.clicked.connect(self.export_file_list)

        # 添加按钮到布局
        action_layout.addWidget(self.save_selected_btn)
        action_layout.addWidget(self.save_all_btn)
        action_layout.addWidget(self.export_list_btn)

        # 添加右侧弹簧使按钮居中
        action_layout.addStretch()

        main_layout.addWidget(action_frame)

    def export_stats(self):
        """导出统计信息"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "保存文件",
            f"stats_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV 文件 (*.csv);;所有文件 (*)"
        )

        if file_name:
            try:
                with open(file_name, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', '访问次数', '状态码', '来源IP', '方法', "UA"])

                    for url, stats in self.url_stats.items():
                        status_text = "; ".join(f"{k}:{v}" for k, v in stats['status_codes'].items())
                        ip_text = "; ".join(f"{k}:{v}" for k, v in stats['source_ips'].items())
                        method_text = "; ".join(f"{k}:{v}" for k, v in stats['methods'].items())
                        UA = "; ".join(f"{k}:{v}" for k, v in stats['UA'].items())

                        writer.writerow([
                            url,
                            stats['count'],
                            status_text,
                            ip_text,
                            method_text,
                            UA
                        ])

                self.status_label.setText("统计信息已成功导出")
                self.add_recent_activity("导出统计", file_name, "成功")
                QMessageBox.information(self, "成功", "统计信息已成功导出！")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
                self.add_recent_activity("导出统计", file_name, f"失败: {str(e)}")

    def find_request(self):
        """查找指定ID的请求"""

        file = self.Import_box.text()
        if not file:
            QMessageBox.warning(self, "警告", "请先选择流量文件!")
            return

        self.memory_optimization = False  # 当值变成了真会叫数据写入到硬盘里面
        self.status_create_replay_tab.setText("")
        base_name = os.path.basename(file)  # 取文件名，比如 gsl.cap
        folder_name = os.path.splitext(base_name)[0]  # 去掉扩展名，比如 gsl
        self.start_analysis_timestamp = folder_name+"_"+datetime.datetime.now().strftime("%Y%m%d_%H%M%S")+".txt"

        # 清除之前的结果
        self.request_text_edit.clear()

        # 启动分析线程
        self.replay_thread = AnalysisThread(
            file=file,
            uri="",
            keyword="",
            output="",
            request_only=True,
            response_only=False,
            show_body=True,
        )
        self.replay_thread.analysis_similar = "pyshark" if self.replay_pyshark_radio.isChecked() else "tshark"
        self.replay_thread.result_signal.connect(self.update_replay_request)
        self.replay_thread.finished_signal.connect(self.replay_finished)

        self.find_request_button.setEnabled(False)
        self.stop_replay_button.setEnabled(True)
        self.status_label.setText("正在查找请求...")
        self.replay_thread.start()

        self.add_recent_activity("查找请求", file, "进行中")

    def replay_request(self):
        """重放请求"""
        global proxies
        proxies = self.get_proxy_settings()

        # 清除之前的结果
        self.request_text_edit.clear()

        file = self.Import_box.text()
        if not file:
            QMessageBox.warning(self, "警告", "请先选择流量文件!")
            return

        stream_id = self.stream_id_input.text().strip()
        if not stream_id:
            QMessageBox.warning(self, "警告", "请输入要查找的请求ID!")
            return

        # 启动分析线程
        self.replay_thread = AnalysisThread(
            file=file,
            uri="",
            keyword="",
            output="",
            request_only=True,
            response_only=False,
            show_body=True,
            request_stream_id=stream_id,
        )

        self.replay_thread.analysis_similar = "tshark" if self.replay_tshark_radio.isChecked() else "pyshark"
        self.replay_thread.result_signal.connect(self.update_replay_request)
        self.replay_thread.finished_signal.connect(self.replay_finished)

        self.find_request_button.setEnabled(False)
        self.stop_replay_button.setEnabled(True)
        self.status_label.setText("正在重放请求...")
        self.replay_thread.start()

        self.add_recent_activity("重放请求", file, "进行中")

    def create_report_tab(self):
        """创建报告生成标签页"""
        tab = QWidget()
        self.workspace.addTab(tab, QIcon("ico/report.png"), "报告生成")
        self.tabs["report"] = tab

        layout = QVBoxLayout(tab)

        # 报告配置区域
        config_group = QGroupBox("报告配置")
        config_layout = QFormLayout(config_group)

        self.report_title = QLineEdit("网络流量分析报告")
        self.report_author = QLineEdit()
        self.report_company = QLineEdit()
        self.report_date = QLineEdit(datetime.datetime.now().strftime("%Y-%m-%d"))

        self.include_stats = QCheckBox("包含统计信息")
        self.include_stats.setChecked(True)
        self.include_charts = QCheckBox("包含图表")
        self.include_charts.setChecked(True)
        self.include_details = QCheckBox("包含详细请求")
        self.include_details.setChecked(False)

        config_layout.addRow("报告标题:", self.report_title)
        config_layout.addRow("作者:", self.report_author)
        config_layout.addRow("公司:", self.report_company)
        config_layout.addRow("日期:", self.report_date)
        config_layout.addRow(self.include_stats)
        config_layout.addRow(self.include_charts)
        config_layout.addRow(self.include_details)

        # 报告预览区域
        preview_group = QGroupBox("报告预览")
        preview_layout = QVBoxLayout(preview_group)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        preview_layout.addWidget(self.report_preview)

        # 操作按钮
        button_layout = QHBoxLayout()
        self.generate_btn = QPushButton("生成报告预览")
        self.generate_btn.clicked.connect(self.generate_report_preview)
        self.export_pdf_btn = QPushButton("导出PDF")
        self.export_pdf_btn.clicked.connect(self.export_report_pdf)
        self.export_html_btn = QPushButton("导出HTML")
        self.export_html_btn.clicked.connect(self.export_report_html)

        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.export_pdf_btn)
        button_layout.addWidget(self.export_html_btn)

        layout.addWidget(config_group)
        layout.addWidget(preview_group)
        layout.addLayout(button_layout)

    def generate_report_preview(self):
        """生成报告预览"""
        """生成美观的报告预览"""
        if not self.url_stats:
            QMessageBox.warning(self, "警告", "没有可用的分析数据!")
            return

        try:
            # 获取报告配置
            title = self.report_title.text()
            author = self.report_author.text()
            company = self.report_company.text()
            date = self.report_date.text()

            # 定义CSS样式
            css_style = """
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                h1, h2, h3 {
                    color: #2c3e50;
                    margin-top: 30px;
                }
                h1 {
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                    box-shadow: 0 2px 3px rgba(0,0,0,0.1);
                }
                th {
                    background-color: #3498db;
                    color: white;
                    text-align: left;
                    padding: 12px;
                }
                td {
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }
                tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
                tr:hover {
                    background-color: #e6f7ff;
                }
                .summary-card {
                    background: white;
                    border-radius: 5px;
                    padding: 20px;
                    margin: 20px 0;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }
                .card-container {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 20px;
                    margin: 20px 0;
                }
                .card {
                    flex: 1;
                    min-width: 200px;
                    background: white;
                    border-radius: 5px;
                    padding: 15px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }
                .card h3 {
                    margin-top: 0;
                    color: #3498db;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                }
                .status-code {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-weight: bold;
                    font-size: 0.8em;
                }
                .status-2xx { background-color: #2ecc71; color: white; }
                .status-3xx { background-color: #f39c12; color: white; }
                .status-4xx { background-color: #e74c3c; color: white; }
                .status-5xx { background-color: #9b59b6; color: white; }
                .logo {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .logo img {
                    max-width: 200px;
                }
            </style>
            """

            # 构建报告内容
            report_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{title}</title>
                <meta charset="UTF-8">
                {css_style}
            </head>
            <body>
                <div class="logo">
                    <h1>{title}</h1>
                </div>

                <div class="summary-card">
                    <p><strong>生成时间:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>作者:</strong> {author if author else '未指定'}</p>
                    <p><strong>公司/组织:</strong> {company if company else '未指定'}</p>
                </div>

                <h2>分析概览</h2>
                {self._generate_summary_cards()}
            """

            # 添加统计信息
            if self.include_stats.isChecked():
                report_content += """
                <h2>详细统计</h2>
                <h3>请求统计</h3>
                """ + self._generate_request_stats_table()

            # 添加图表信息
            if self.include_charts.isChecked():
                report_content += """
                <h3>状态码分布</h3>
                """ + self._generate_status_code_chart()

                report_content += """
                <h3>来源IP统计 (TOP 10)</h3>
                """ + self._generate_ip_stats_table()

            # 添加详细请求信息
            if self.include_details.isChecked():
                report_content += """
                <h2>详细请求信息</h2>
                """ + self._generate_detailed_requests_table()

            # 添加结论
            report_content += """
                <h2>分析结论</h2>
                <div class="summary-card">
                    <p>请在此处添加分析结论和建议...</p>
                </div>
            </body>
            </html>
            """

            self.report_preview.setHtml(report_content)
            self.status_label.setText("报告预览生成成功")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成报告时出错: {str(e)}")
            self.status_label.setText("报告生成失败")

    def _generate_summary_cards(self):
        """生成摘要卡片"""
        total_requests = sum(stats['count'] for stats in self.url_stats.values())
        unique_urls = len(self.url_stats)

        source_ips = set()
        status_codes = set()
        methods = set()

        for stats in self.url_stats.values():
            source_ips.update(stats['source_ips'].keys())
            status_codes.update(stats['status_codes'].keys())
            methods.update(stats['methods'].keys())

        return f"""
        <div class="card-container">
            <div class="card">
                <h3>总请求数</h3>
                <p style="font-size: 24px; font-weight: bold; color: #3498db;">{total_requests}</p>
            </div>
            <div class="card">
                <h3>唯一URL</h3>
                <p style="font-size: 24px; font-weight: bold; color: #2ecc71;">{unique_urls}</p>
            </div>
            <div class="card">
                <h3>来源IP</h3>
                <p style="font-size: 24px; font-weight: bold; color: #e74c3c;">{len(source_ips)}</p>
            </div>
            <div class="card">
                <h3>HTTP方法</h3>
                <p style="font-size: 24px; font-weight: bold; color: #9b59b6;">{len(methods)}</p>
            </div>
        </div>
        """

    def _generate_request_stats_table(self):
        """生成请求统计表格"""
        stats_by_url = sorted(
            self.url_stats.items(),
            key=lambda item: item[1]['count'],
            reverse=True
        )[:20]  # 只显示前20个URL

        rows = []
        for url, stats in stats_by_url:
            status_codes = "<br>".join(
                f'<span class="status-code status-{code[0]}xx">{code}</span>: {count}'
                for code, count in stats['status_codes'].items()
            )

            rows.append(f"""
            <tr>
                <td><a href="{url}" target="_blank">{url[:80] + '...' if len(url) > 80 else url}</a></td>
                <td>{stats['count']}</td>
                <td>{status_codes}</td>
                <td>{len(stats['source_ips'])}</td>
                <td>{', '.join(stats['methods'].keys())}</td>
            </tr>
            """)

        return f"""
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>请求数</th>
                    <th>状态码分布</th>
                    <th>来源IP数</th>
                    <th>HTTP方法</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        """

    def _generate_status_code_chart(self):
        """生成状态码分布图表(HTML版)"""
        status_counts = defaultdict(int)
        for stats in self.url_stats.values():
            for code, count in stats['status_codes'].items():
                status_counts[code] += count

        # 按状态码分类排序
        sorted_codes = sorted(status_counts.items(), key=lambda x: x[0])

        # 生成HTML图表
        chart_html = """
        <div style="display: flex; justify-content: space-between; margin: 20px 0;">
        """

        total = sum(status_counts.values())
        for code, count in sorted_codes:
            percentage = (count / total) * 100
            color_class = f"status-{code[0]}xx"

            chart_html += f"""
            <div style="text-align: center; flex: 1;">
                <div class="status-code {color_class}" style="margin: 0 auto 10px; font-size: 16px;">
                    {code}
                </div>
                <div style="height: {percentage}px; background-color: {'#3498db' if code.startswith('2') else '#f39c12' if code.startswith('3') else '#e74c3c' if code.startswith('4') else '#9b59b6'}; 
                    width: 80%; margin: 0 auto; border-radius: 3px 3px 0 0;"></div>
                <div style="margin-top: 5px;">{count}<br><small>({percentage:.1f}%)</small></div>
            </div>
            """

        chart_html += "</div>"
        return chart_html

    def _generate_ip_stats_table(self):
        """生成美观的IP统计表格"""
        ip_counts = defaultdict(int)
        for stats in self.url_stats.values():
            for ip, count in stats['source_ips'].items():
                ip_counts[ip] += count

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        rows = []
        for ip, count in top_ips:
            percentage = (count / top_ips[0][1]) * 100
            rows.append(f"""
            <tr>
                <td>{ip}</td>
                <td class="text-right">{count:,}</td>
                <td>
                    <div class="progress-container">
                        <div class="progress-bar" style="width: {percentage}%"></div>
                        <span class="progress-text">{percentage:.1f}%</span>
                    </div>
                </td>
            </tr>
            """)

        return f"""
        <div class="report-section">
            <h3>TOP IP地址统计</h3>
            <div class="table-container">
                <table class="styled-table">
                    <thead>
                        <tr>
                            <th>IP地址</th>
                            <th class="text-right">请求数</th>
                            <th>比例</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """

    def _generate_detailed_requests_table(self):
        """生成美观的详细请求表格"""
        top_requests = sorted(
            self.url_stats.items(),
            key=lambda item: item[1]['count'],
            reverse=True
        )[:50]  # 只显示前50个请求

        rows = []
        for url, stats in top_requests:
            status_codes = "<br>".join(
                f'<span class="status-code status-{str(code)[0]}xx">{code}</span>: {count:,}'
                for code, count in sorted(stats['status_codes'].items(), key=lambda x: x[1], reverse=True)
            )

            source_ips = "<br>".join(
                f"{ip}: {count:,}"
                for ip, count in sorted(stats['source_ips'].items(), key=lambda x: x[1], reverse=True)[:3]
            )

            methods = "<br>".join(
                f"{method}: {count:,}"
                for method, count in sorted(stats['methods'].items(), key=lambda x: x[1], reverse=True)
            )

            user_agents = "<br>".join(
                f'<span title="{ua}">{ua[:50]}...</span>: {count:,}' if len(ua) > 50 else f"{ua}: {count:,}"
                for ua, count in sorted(stats['UA'].items(), key=lambda x: x[1], reverse=True)[:3]
            )

            rows.append(f"""
            <tr>
                <td class="url-cell"><a href="{url}" target="_blank" title="{url}">{url[:80] + '...' if len(url) > 80 else url}</a></td>
                <td class="text-right">{stats['count']:,}</td>
                <td>{status_codes}</td>
                <td>{source_ips}</td>
                <td>{methods}</td>
                <td class="ua-cell">{user_agents}</td>
            </tr>
            """)

        return f"""
        <div class="report-section">
            <h3>详细请求统计 (TOP 50)</h3>
            <div class="table-container wide">
                <table class="styled-table detailed">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th class="text-right">总请求</th>
                            <th>状态码</th>
                            <th>主要来源IP</th>
                            <th>HTTP方法</th>
                            <th>User-Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """

    def generate_report_styles(self):
        """生成报告CSS样式"""
        return """
        <style>
            .report-section {
                margin-bottom: 30px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 20px;
                overflow: hidden;
            }

            .report-section h3 {
                margin-top: 0;
                color: #2c3e50;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }

            .table-container {
                overflow-x: auto;
            }

            .table-container.wide {
                width: 100%;
            }

            .styled-table {
                width: 100%;
                border-collapse: collapse;
                font-size: 14px;
            }

            .styled-table th {
                background-color: #f8f9fa;
                color: #495057;
                font-weight: 600;
                text-align: left;
                padding: 12px 15px;
                border-bottom: 2px solid #dee2e6;
            }

            .styled-table td {
                padding: 12px 15px;
                border-bottom: 1px solid #dee2e6;
                vertical-align: top;
            }

            .styled-table tr:hover td {
                background-color: #f8f9fa;
            }

            .styled-table.detailed td {
                white-space: nowrap;
            }

            .text-right {
                text-align: right;
            }

            .url-cell {
                max-width: 200px;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .ua-cell {
                max-width: 250px;
            }

            .progress-container {
                position: relative;
                height: 24px;
                background-color: #e9ecef;
                border-radius: 4px;
            }

            .progress-bar {
                height: 100%;
                background-color: #3498db;
                border-radius: 4px;
                transition: width 0.3s ease;
            }

            .progress-text {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                color: #fff;
                font-size: 12px;
                font-weight: bold;
                text-shadow: 0 0 2px rgba(0,0,0,0.5);
            }

            .status-code {
                display: inline-block;
                padding: 2px 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 12px;
            }

            .status-2xx {
                background-color: #d4edda;
                color: #155724;
            }

            .status-3xx {
                background-color: #fff3cd;
                color: #856404;
            }

            .status-4xx {
                background-color: #f8d7da;
                color: #721c24;
            }

            .status-5xx {
                background-color: #d1ecf1;
                color: #0c5460;
            }
        </style>
        """

    def export_report_pdf(self):
        """导出报告为PDF"""
        if not self.report_preview.toPlainText():
            QMessageBox.warning(self, "警告", "没有可导出的报告内容!")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出PDF报告",
            f"TrafficEye_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            "PDF文件 (*.pdf)"
        )

        if not file_path:
            return

        try:
            # 创建打印机设置
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)

            # 设置页面属性
            page_layout = QPageLayout(
                QPageSize(QPageSize.PageSizeId.A4),
                QPageLayout.Orientation.Portrait,
                QMarginsF(15, 15, 15, 15),  # 1.5cm边距
                QPageLayout.Unit.Millimeter
            )
            printer.setPageLayout(page_layout)

            # 创建文档对象
            document = QTextDocument()
            document.setHtml(self.report_preview.toHtml())

            # 设置文档属性
            document.setPageSize(printer.pageRect(QPrinter.Unit.Point).size())

            # 显示进度对话框
            progress = QProgressDialog("正在生成PDF报告...", "取消", 0, 100, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.show()

            # 打印到PDF
            def draw_all_pages(painter):
                page_count = document.pageCount()
                for page in range(page_count):
                    if progress.wasCanceled():
                        return False

                    progress.setValue(int((page / page_count) * 100))
                    QApplication.processEvents()

                    if page > 0:
                        printer.newPage()

                    painter.drawText(
                        printer.pageRect(QPrinter.Unit.Point),
                        Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap,
                        document.toHtml()
                    )

                return True

            painter = QPainter(printer)
            success = draw_all_pages(painter)
            painter.end()

            progress.close()

            if success:
                # 询问是否打开PDF
                reply = QMessageBox.question(
                    self, "导出成功",
                    "PDF报告已成功生成!\n是否要立即打开查看?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.Yes:
                    self._open_file(file_path)

                self.status_label.setText(f"PDF报告已保存到: {file_path}")
                self.add_recent_activity("导出PDF报告", file_path, "成功")
            else:
                QMessageBox.information(self, "信息", "PDF生成已取消")

        except Exception as e:
            progress.close()
            QMessageBox.critical(self, "错误", f"导出PDF失败: {str(e)}")
            self.add_recent_activity("导出PDF报告", file_path, f"失败: {str(e)}")

    def _open_file(self, file_path):
        """跨平台打开文件"""
        try:
            if sys.platform == "win32":
                os.startfile(file_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", file_path])
            else:
                subprocess.run(["xdg-open", file_path])
        except Exception as e:
            QMessageBox.warning(self, "警告", f"无法打开文件: {str(e)}")

    def export_report_html(self):
        """导出报告为HTML"""
        if not self.report_preview.toPlainText():
            QMessageBox.warning(self, "警告", "没有可导出的报告内容!")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出HTML报告",
            f"TrafficEye_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML文件 (*.html)"
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.report_preview.toHtml())

                QMessageBox.information(self, "成功", "HTML报告导出成功!")
                self.status_label.setText(f"HTML报告已导出到: {file_path}")
                self.add_recent_activity("导出HTML报告", file_path, "成功")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出HTML失败: {str(e)}")
                self.add_recent_activity("导出HTML报告", file_path, f"失败: {str(e)}")

    def update_replay_request(self, text):
        """更新请求显示"""
        self.request_text_edit.append(text)
        self.memory_optimization_invoke(self.request_text_edit,self.status_create_replay_tab, text=text)



    def clear_replay_results(self):
        """清除重放结果"""
        self.request_text_edit.clear()
        if hasattr(self, 'current_request'):
            del self.current_request
        self.status_label.setText("结果已清除")

    def stop_replay(self):
        """停止查找请求"""
        if self.replay_thread and self.replay_thread.isRunning():
            self.replay_thread.terminate()
            self.replay_thread.wait()
            self.request_text_edit.append("\n操作已停止!")
            self.status_label.setText("操作已停止")
            self.add_recent_activity("停止操作", self.Import_box.text(), "已停止")

        self.find_request_button.setEnabled(True)
        self.stop_replay_button.setEnabled(False)

    def replay_finished(self):
        """查找请求完成"""
        self.find_request_button.setEnabled(True)
        self.stop_replay_button.setEnabled(False)
        self.status_label.setText("操作完成")
        self.add_recent_activity("请求操作", self.Import_box.text(), "完成")

    def cleanup_resources(self):
        """ 清理图表资源 """
        if hasattr(self, '_status_chart'):
            self._status_chart.deleteLater()

        # # 清理线程
        # if hasattr(self, 'analysis_thread') and self.analysis_thread.isRunning():
        #     self.analysis_thread.terminate()
        #     self.analysis_thread.wait()

        # 清理模型数据
        if hasattr(self, 'url_table_model'):
            self.url_table_model.deleteLater()

    def closeEvent(self, event):
        """窗口关闭事件"""

        self.cleanup_resources()
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_thread.terminate()
            self.analysis_thread.wait()

        if self.replay_thread and self.replay_thread.isRunning():
            self.replay_thread.terminate()
            self.replay_thread.wait()

        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    font = QFont()
    font.setFamily("Segoe UI")
    font.setPointSize(10)
    app.setFont(font)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())
