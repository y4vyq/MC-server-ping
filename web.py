import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from mc_pinger import MinecraftPinger

# 配置
HOST = '0.0.0.0'
PORT = 5000
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')


def render_template(template_name):
    """简单读取并返回 HTML 文件内容"""
    path = os.path.join(TEMPLATE_DIR, template_name)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>404 Template Not Found</h1>"


class MinecraftQueryHandler(BaseHTTPRequestHandler):
    """处理 HTTP 请求"""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query_params = parse_qs(parsed.query)

        # 路由分发
        if path == '/':
            self.handle_index()
        elif path == '/query':
            self.handle_query(query_params)
        else:
            self.send_error(404, "Not Found")

    def handle_index(self):
        """返回前端页面"""
        html = render_template('index.html')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def handle_query(self, params):
        """查询 API"""
        host = params.get('host', ['127.0.0.1'])[0]
        port_str = params.get('port', ['25565'])[0]
        try:
            port = int(port_str)
        except ValueError:
            self.send_json({"error": "端口号必须为数字!"}, 400)
            return

        pinger = MinecraftPinger(host, port, timeout=5.0)
        result = pinger.query()
        self.send_json(result, 200)

    def send_json(self, data, status=200):
        """发送 JSON 响应"""
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    server = HTTPServer((HOST, PORT), MinecraftQueryHandler)
    print(f"服务器启动于 http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已关闭")
        server.server_close()
