import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import subprocess
import re
import psutil
import threading
import time
from datetime import datetime

class PortManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Forwi")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # 设置主题样式
        self.style = ttk.Style()
        self.style.configure("Treeview.Heading", font=("微软雅黑", 10, "bold"))
        self.style.configure("Treeview", font=("微软雅黑", 10))
        
        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建顶部控制区域
        self.create_control_frame()
        
        # 创建表格视图
        self.create_table_view()
        
        # 创建日志区域
        self.create_log_frame()
        
        # 开始自动刷新端口列表
        self.running = True
        self.refresh_thread = threading.Thread(target=self.auto_refresh_ports, daemon=True)
        self.refresh_thread.start()
        
        # 窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_control_frame(self):
        control_frame = ttk.LabelFrame(self.main_frame, text="控制面板", padding="10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # 刷新按钮
        self.refresh_btn = ttk.Button(control_frame, text="刷新端口列表", command=self.refresh_ports)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # 关闭端口按钮
        self.close_port_btn = ttk.Button(control_frame, text="关闭选中端口", command=self.close_selected_port)
        self.close_port_btn.pack(side=tk.LEFT, padx=5)
        
        # 端口扫描按钮
        self.scan_btn = ttk.Button(control_frame, text="扫描端口", command=self.scan_ports_dialog)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        # 网络连接详情按钮
        self.details_btn = ttk.Button(control_frame, text="查看连接详情", command=self.show_connection_details)
        self.details_btn.pack(side=tk.LEFT, padx=5)
        
        # 刷新间隔设置
        refresh_frame = ttk.Frame(control_frame)
        refresh_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(refresh_frame, text="自动刷新间隔(秒):").pack(side=tk.LEFT)
        self.refresh_interval = tk.StringVar(value="5")
        ttk.Entry(refresh_frame, textvariable=self.refresh_interval, width=5).pack(side=tk.LEFT, padx=5)
        ttk.Button(refresh_frame, text="应用", command=self.apply_refresh_interval).pack(side=tk.LEFT)
    
    def create_table_view(self):
        table_frame = ttk.LabelFrame(self.main_frame, text="端口列表", padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建表格
        columns = ("protocol", "local_address", "local_port", "remote_address", 
                  "remote_port", "status", "pid", "process")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # 设置列标题
        self.tree.heading("protocol", text="协议")
        self.tree.heading("local_address", text="本地地址")
        self.tree.heading("local_port", text="本地端口")
        self.tree.heading("remote_address", text="远程地址")
        self.tree.heading("remote_port", text="远程端口")
        self.tree.heading("status", text="状态")
        self.tree.heading("pid", text="PID")
        self.tree.heading("process", text="进程名")
        
        # 设置列宽
        self.tree.column("protocol", width=60)
        self.tree.column("local_address", width=120)
        self.tree.column("local_port", width=80)
        self.tree.column("remote_address", width=120)
        self.tree.column("remote_port", width=80)
        self.tree.column("status", width=80)
        self.tree.column("pid", width=60)
        self.tree.column("process", width=150)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # 双击事件
        self.tree.bind("<Double-1>", self.on_item_double_click)
    
    def create_log_frame(self):
        log_frame = ttk.LabelFrame(self.main_frame, text="操作日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建日志文本框
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, height=6, font=("微软雅黑", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 添加滚动条
        log_scrollbar = ttk.Scrollbar(self.log_text, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscroll=log_scrollbar.set)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 设置文本框为只读
        self.log_text.config(state=tk.DISABLED)
    
    def log_message(self, message):
        """添加日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def get_ports_info(self):
        """获取系统端口信息"""
        try:
            connections = psutil.net_connections()
            port_info = []
            
            for conn in connections:
                if conn.status == 'LISTEN' or conn.status == 'ESTABLISHED':
                    protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    local_addr = conn.laddr[0] if conn.laddr else ''
                    local_port = conn.laddr[1] if conn.laddr else ''
                    remote_addr = conn.raddr[0] if conn.raddr else ''
                    remote_port = conn.raddr[1] if conn.raddr else ''
                    
                    # 获取进程信息
                    process_name = "N/A"
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except:
                            process_name = "Access Denied"
                    
                    port_info.append((
                        protocol,
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        conn.status,
                        conn.pid or "N/A",
                        process_name
                    ))
            
            return port_info
        except Exception as e:
            self.log_message(f"获取端口信息时出错: {str(e)}")
            return []
    
    def refresh_ports(self):
        """刷新端口列表"""
        # 清空表格
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 获取端口信息
        ports_info = self.get_ports_info()
        
        # 按端口号排序
        ports_info.sort(key=lambda x: x[2] if isinstance(x[2], int) else 0)
        
        # 添加到表格
        for port in ports_info:
            self.tree.insert("", tk.END, values=port)
        
        self.log_message(f"已刷新端口列表，共 {len(ports_info)} 个连接")
    
    def auto_refresh_ports(self):
        """自动刷新端口列表线程"""
        while self.running:
            try:
                interval = int(self.refresh_interval.get())
                time.sleep(interval)
                self.root.after(0, self.refresh_ports)
            except ValueError:
                time.sleep(5)
            except Exception as e:
                self.root.after(0, lambda: self.log_message(f"自动刷新出错: {str(e)}"))
                time.sleep(5)
    
    def apply_refresh_interval(self):
        """应用刷新间隔设置"""
        try:
            interval = int(self.refresh_interval.get())
            if interval < 1:
                raise ValueError("间隔不能小于1秒")
            self.log_message(f"已设置自动刷新间隔为 {interval} 秒")
        except ValueError as e:
            messagebox.showerror("错误", str(e))
            self.refresh_interval.set("5")
    
    def close_selected_port(self):
        """关闭选中的端口"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("提示", "请先选择要关闭的端口")
            return
        
        item = selected_item[0]
        values = self.tree.item(item, "values")
        pid = values[6]
        local_port = values[2]
        process_name = values[7]
        
        if pid == "N/A":
            messagebox.showwarning("警告", "无法关闭无PID的端口连接")
            return
        
        # 确认对话框
        confirm = messagebox.askyesno(
            "确认关闭", 
            f"确定要关闭 PID {pid} ({process_name}) 占用的端口 {local_port} 吗？\n这可能会导致相关应用程序功能异常。"
        )
        
        if confirm:
            try:
                process = psutil.Process(int(pid))
                process.terminate()
                self.log_message(f"已终止进程 PID {pid} ({process_name})，端口 {local_port}")
                # 刷新端口列表
                self.root.after(1000, self.refresh_ports)
            except Exception as e:
                self.log_message(f"关闭端口失败: {str(e)}")
                messagebox.showerror("错误", f"关闭端口失败: {str(e)}")
    
    def scan_ports_dialog(self):
        """端口扫描对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("端口扫描")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 居中显示
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (self.root.winfo_width() // 2) - (width // 2) + self.root.winfo_x()
        y = (self.root.winfo_height() // 2) - (height // 2) + self.root.winfo_y()
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # 创建输入框
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="目标IP地址:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frame, textvariable=ip_var, width=20).grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="起始端口:").grid(row=1, column=0, sticky=tk.W, pady=5)
        start_port_var = tk.StringVar(value="1")
        ttk.Entry(frame, textvariable=start_port_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="结束端口:").grid(row=2, column=0, sticky=tk.W, pady=5)
        end_port_var = tk.StringVar(value="1024")
        ttk.Entry(frame, textvariable=end_port_var, width=10).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # 扫描结果文本框
        ttk.Label(frame, text="扫描结果:").grid(row=3, column=0, sticky=tk.NW, pady=5)
        result_text = tk.Text(frame, wrap=tk.WORD, height=5, width=30, state=tk.DISABLED)
        result_text.grid(row=3, column=1, pady=5)
        
        # 按钮区域
        btn_frame = ttk.Frame(dialog, padding="10")
        btn_frame.pack(fill=tk.X)
        
        def start_scan():
            # 验证输入
            try:
                ip = ip_var.get()
                start_port = int(start_port_var.get())
                end_port = int(end_port_var.get())
                
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError("端口范围无效")
                
                # 清空结果
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.config(state=tk.DISABLED)
                
                # 禁用按钮
                scan_btn.config(state=tk.DISABLED)
                cancel_btn.config(state=tk.DISABLED)
                
                # 在新线程中执行扫描
                def scan_thread():
                    open_ports = self.scan_ports(ip, start_port, end_port, lambda msg: 
                        result_text.after(0, lambda: update_result(msg)))
                    
                    self.root.after(0, lambda: finish_scan(open_ports))
                
                def update_result(message):
                    result_text.config(state=tk.NORMAL)
                    result_text.insert(tk.END, message + "\n")
                    result_text.see(tk.END)
                    result_text.config(state=tk.DISABLED)
                
                def finish_scan(open_ports):
                    update_result(f"\n扫描完成，发现 {len(open_ports)} 个开放端口")
                    scan_btn.config(state=tk.NORMAL)
                    cancel_btn.config(state=tk.NORMAL)
                    self.log_message(f"端口扫描完成: {ip} 从 {start_port} 到 {end_port}，发现 {len(open_ports)} 个开放端口")
                
                threading.Thread(target=scan_thread, daemon=True).start()
                
            except ValueError as e:
                messagebox.showerror("输入错误", str(e))
        
        scan_btn = ttk.Button(btn_frame, text="开始扫描", command=start_scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(btn_frame, text="取消", command=dialog.destroy)
        cancel_btn.pack(side=tk.RIGHT, padx=5)
    
    def scan_ports(self, ip, start_port, end_port, update_callback):
        """扫描指定IP的端口范围"""
        open_ports = []
        total_ports = end_port - start_port + 1
        
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service = self.get_service_name(port)
                open_ports.append(port)
                update_callback(f"端口 {port} 开放 - {service}")
            
            # 每10个端口更新一次进度
            if (port - start_port) % 10 == 0:
                progress = (port - start_port + 1) / total_ports * 100
                update_callback(f"扫描进度: {progress:.1f}%")
            
            sock.close()
        
        return open_ports
    
    def get_service_name(self, port):
        """根据端口号获取常见服务名称"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
            5432: "PostgreSQL", 27017: "MongoDB", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return common_ports.get(port, "未知服务")
    
    def show_connection_details(self):
        """显示选中连接的详细信息"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("提示", "请先选择一个连接")
            return
        
        item = selected_item[0]
        values = self.tree.item(item, "values")
        protocol = values[0]
        local_addr = values[1]
        local_port = values[2]
        remote_addr = values[3]
        remote_port = values[4]
        status = values[5]
        pid = values[6]
        process_name = values[7]
        
        # 创建详细信息对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("连接详情")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        
        # 创建详情文本框
        text = tk.Text(dialog, wrap=tk.WORD, font=("微软雅黑", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 添加详细信息
        details = f"""协议: {protocol}
本地地址: {local_addr}
本地端口: {local_port}
远程地址: {remote_addr}
远程端口: {remote_port}
连接状态: {status}
进程ID: {pid}
进程名称: {process_name}
        """
        
        # 如果有PID，尝试获取更多进程信息
        if pid != "N/A":
            try:
                process = psutil.Process(int(pid))
                details += f"\n进程详情:\n"
                details += f"创建时间: {datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')}\n"
                details += f"CPU使用率: {process.cpu_percent(interval=0.1)}%\n"
                details += f"内存使用: {process.memory_info().rss / 1024 / 1024:.2f} MB\n"
                details += f"命令行: {' '.join(process.cmdline()) if process.cmdline() else 'N/A'}\n"
            except:
                details += "\n无法获取更多进程信息（权限不足）\n"
        
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)
        
        # 添加关闭按钮
        ttk.Button(dialog, text="关闭", command=dialog.destroy).pack(pady=10)
    
    def on_item_double_click(self, event):
        """双击项目时显示详情"""
        self.show_connection_details()
    
    def on_closing(self):
        """窗口关闭事件处理"""
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    try:
        # 检查是否以管理员权限运行
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
        root = tk.Tk()
        
        # 设置中文显示
        root.option_add("*Font", ("微软雅黑", 10))
        
        app = PortManagerApp(root)
        
        # 如果不是管理员权限，显示警告
        if not is_admin:
            app.log_message("警告: 程序未以管理员权限运行，可能无法关闭某些系统进程占用的端口")
        
        root.mainloop()
    except Exception as e:
        print(f"程序启动失败: {str(e)}")
        input("按Enter键退出...")