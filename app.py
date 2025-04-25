import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
from flask import Flask, render_template, request, send_file, redirect, session, make_response, abort
from werkzeug.utils import safe_join
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import json
import threading

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key_here')  # 请更改为真实的密钥

# 配置
UPLOAD_DIR = 'uploads'
LOG_FILE = 'access.log'
UPLOAD_PASSWORD = 'password'  # 上传密码

# 确保上传目录存在
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 日志配置，同时保存到文件和打印到控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

# 邀请码配置  前面是邀请码ID remark是邀请码备注（名称） id_admin字面意思
INVITE_CODES = {
    'admin888': {'remark': '管理员', 'is_admin': True},
}

# 数据存储
download_counts = {}
review_status = {}
messages = {}
global_reminders = []

# 加载下载计数
try:
    with open('download_counts.json', 'r', encoding='utf-8') as f:
        download_counts = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    pass

# 线程锁
download_lock = threading.Lock()

# 辅助函数
def get_current_user():
    """获取当前用户信息"""
    if 'invited' not in session:
        return None

    invite_code = session.get('invite_code')
    if not invite_code or invite_code not in INVITE_CODES:
        return None

    return {
        'code': invite_code,
        'name': INVITE_CODES[invite_code]['remark'],
        'is_admin': INVITE_CODES[invite_code]['is_admin']
    }

def save_download_counts():
    """保存下载计数"""
    with download_lock:
        try:
            with open('download_counts.json', 'w', encoding='utf-8') as f:
                json.dump(download_counts, f, ensure_ascii=False, indent=2)
        except IOError as e:
            logger.error(f"保存下载计数失败: {str(e)}")

# 首页
@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect('/invite')

    # 获取文件列表
    files = []
    for filename in os.listdir(UPLOAD_DIR):
        filepath = os.path.join(UPLOAD_DIR, filename)
        if os.path.isfile(filepath):
            file_info = review_status.get(filename, {})
            files.append({
                'filename': filename,
                'created': datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
                'download_count': download_counts.get(filename, 0),
                'size': round(os.path.getsize(filepath) / (1024 * 1024), 2),
                'uploader': file_info.get('uploader', '未知'),
                'status': file_info.get('status', '待审核')
            })

    files.sort(key=lambda x: x['created'], reverse=True)
    logger.info(f"用户 {user['name']} 访问首页。IP: {request.remote_addr}")

    return render_template(
        'index.html',
        files=files,
        username=user['name'],
        is_admin=user['is_admin'],
        global_reminders=global_reminders
    )

# 邀请码验证
@app.route('/invite', methods=['GET', 'POST'])
def invite():
    if request.method == 'POST':
        code = request.form.get('invite_code', '').strip()
        if code in INVITE_CODES:
            session['invited'] = True
            session['invite_code'] = code
            resp = make_response(redirect('/'))
            resp.set_cookie('logged_in', 'true', httponly=True, secure=True)
            logger.info(f"用户 {INVITE_CODES[code]['remark']} 使用邀请码登录。IP: {request.remote_addr}")
            return resp
        return render_template('invite.html', error='邀请码错误')

    return render_template('invite.html')

# 文件上传
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user = get_current_user()
    if not user:
        return redirect('/invite')

    if request.method == 'POST':
        if request.form.get('upload_password') != UPLOAD_PASSWORD:
            return render_template('upload.html', error='上传密码错误', username=user['name'])

        file = request.files.get('file')
        if not file or file.filename.strip() == '':
            return render_template('upload.html', error='未选择文件', username=user['name'])

        filename = file.filename
        try:
            file.save(os.path.join(UPLOAD_DIR, filename))
            review_status[filename] = {
                'status': '待审核',
                'uploader': user['name'],
                'upload_time': datetime.now().isoformat()
            }
            logger.info(f"用户 {user['name']} 上传文件: {filename}, IP: {request.remote_addr}")
            return render_template('upload_success.html', username=user['name'])
        except Exception as e:
            logger.error(f"文件上传失败: {str(e)}")
            return render_template('upload.html', error='文件上传失败', username=user['name'])

    return render_template('upload.html', username=user['name'])

# 文件下载
@app.route('/download/<filename>')
def download(filename):
    user = get_current_user()
    if not user:
        return redirect('/invite')

    filepath = safe_join(UPLOAD_DIR, filename)
    if not os.path.isfile(filepath):
        abort(404)

    file_status = review_status.get(filename, {}).get('status', '待审核')
    if file_status != '通过' and not user['is_admin']:
        return render_template('error.html',
                               message="文件未通过审核，无法下载",
                               username=user['name']), 403

    # 更新下载计数
    download_counts[filename] = download_counts.get(filename, 0) + 1
    save_download_counts()

    logger.info(f"用户 {user['name']} 下载文件: {filename}, IP: {request.remote_addr}")
    # 检查文件是否为 HTML 或图片文件
    if filename.lower().endswith(('.html', '.jpg', '.jpeg', '.png', '.gif')):
        return send_file(filepath, mimetype='text/html' if filename.lower().endswith('.html') else 'image/*')
    return send_file(filepath, as_attachment=True)

# 管理后台
@app.route('/admin')
def admin():
    user = get_current_user()
    if not user or not user['is_admin']:
        abort(403)

    files = []
    for filename in os.listdir(UPLOAD_DIR):
        filepath = os.path.join(UPLOAD_DIR, filename)
        if os.path.isfile(filepath):
            file_info = review_status.get(filename, {})
            files.append({
                'filename': filename,
                'created': datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
                'download_count': download_counts.get(filename, 0),
                'size': round(os.path.getsize(filepath) / (1024 * 1024), 2),
                'uploader': file_info.get('uploader', '未知'),
                'status': file_info.get('status', '待审核'),
                'reason': file_info.get('reason', '')
            })

    files.sort(key=lambda x: x['created'], reverse=True)
    return render_template('admin.html',
                           files=files,
                           username=user['name'],
                           global_reminders=global_reminders)

# 发送全站提醒
@app.route('/admin/send_global_reminder', methods=['POST'])
def send_global_reminder():
    user = get_current_user()
    if not user or not user['is_admin']:
        abort(403)

    reminder = request.form.get('reminder', '').strip()
    if reminder:
        admin_name = user['name']
        global_reminders.append(f"{admin_name}: {reminder}")
        for code in INVITE_CODES:
            messages.setdefault(code, []).append(f"全站提醒: {admin_name}: {reminder}")
        logger.info(f"本站管理员 {user['name']} 发送全站提醒: {reminder}")

    return redirect('/admin')

# 审核文件
@app.route('/admin/review/<filename>/<status>', methods=['POST'])
def review_file(filename, status):
    user = get_current_user()
    if not user or not user['is_admin']:
        abort(403)

    if status not in ['通过', '不通过']:
        abort(400)

    reason = request.form.get('reason', '').strip()
    review_status.setdefault(filename, {})
    review_status[filename]['status'] = status

    if status == '不通过':
        review_status[filename]['reason'] = reason
        # 查找上传者并发送消息
        uploader_name = review_status[filename].get('uploader')
        if uploader_name:
            for code, info in INVITE_CODES.items():
                if info['remark'] == uploader_name:
                    messages.setdefault(code, []).append(
                        f"您上传的文件 {filename} 审核未通过，原因：{reason} 请尝试整改后上传。pp"
                    )
                    break

    logger.info(f"管理员 {user['name']} 审核文件 {filename} 为 {status}，原因：{reason}")
    return redirect('/admin')

# 查看日志
@app.route('/admin/logs')
def view_logs():
    user = get_current_user()
    if not user or not user['is_admin']:
        abort(403)

    logs = []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(' - ', 1)
                if len(parts) == 2:
                    timestamp, message = parts
                    ip_start = message.find('IP: ')
                    if ip_start > 0:
                        action = message[:ip_start].strip()
                        ip = message[ip_start+4:].strip()
                        logs.append({
                            'timestamp': timestamp,
                            'action': action,
                            'ip': ip
                        })
    except FileNotFoundError:
        pass

    return render_template('logs.html', actions=logs, username=user['name'])

# 消息中心
@app.route('/messages')
def messages_page():
    user = get_current_user()
    if not user:
        return redirect('/invite')

    user_messages = messages.get(user['code'], [])
    return render_template('messages.html',
                           messages=user_messages,
                           username=user['name'])

# 退出登录
@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        logger.info(f"用户 {user['name']} 退出登录, IP: {request.remote_addr}")

    session.clear()
    resp = make_response(redirect('/'))
    resp.delete_cookie('logged_in')
    return resp

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)  # 生产环境不要使用 debug=True! 
