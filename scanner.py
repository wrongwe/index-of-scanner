import os
import sys
import re
import csv
import time
import signal
import asyncio
import aiohttp
from urllib.parse import urlparse, urlunparse, urljoin, parse_qs
from collections import defaultdict

from bs4 import BeautifulSoup
from pybloom_live import ScalableBloomFilter
from fake_useragent import UserAgent
import logging

# 配置优化（聚焦敏感文件检测）
CONFIG = {
    "max_depth": 3,  # 限制递归深度
    "request_timeout": 25,
    "concurrency_range": (30, 200),
    "forbidden_ports": {22, 3306, 3389},
    "sensitive_ext": {
        'config', 'ini', 'env', 'zip', 'bak', 'key', 'conf', 'properties',
        'sql', 'db', 'dbf', 'pem', 'crt', 'jks', 'p12', 'audit'
    },
    "sensitive_paths": [
        re.compile(r'/(backup|archive)/', re.I),
        re.compile(r'\.(git|svn)/', re.I)
    ],
    "ignore_ext": {'png', 'jpg', 'jpeg', 'gif'}
}

# 日志系统配置（中文输出）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("scan.log", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)


class ScannerCore:
    def __init__(self):
        self.dedup_filter = ScalableBloomFilter(
            initial_capacity=10000, error_rate=0.001)
        self.ua = UserAgent()
        self.stats = defaultdict(int)
        self.findings = defaultdict(list)
        self.concurrency_sem = asyncio.Semaphore(CONFIG["concurrency_range"][1])
        self._shutdown = False
        self.session = None
        signal.signal(signal.SIGINT, self._graceful_shutdown)

    def _graceful_shutdown(self, signum, frame):
        logging.info("接收到终止信号，正在停止扫描...")
        self._shutdown = True

    async def _process_url(self, raw_url):
        """URL标准化处理"""
        url = raw_url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        parsed = urlparse(url)
        if parsed.port in CONFIG["forbidden_ports"]:
            raise ValueError(f"禁止访问高危端口: {parsed.geturl()}")

        # 清理跟踪参数
        query = parse_qs(parsed.query)
        clean_query = '&'.join(
            f"{k}={v[0]}" for k, v in query.items()
            if not k.startswith('utm_')
        )
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path.rstrip('/'),
            parsed.params, clean_query, parsed.fragment
        ))

    def _detect_sensitive(self, url):
        """敏感文件检测逻辑"""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # 扩展名检测
        if (ext := path.split('.')[-1]) in CONFIG["sensitive_ext"]:
            return (True, f"敏感扩展名: {ext}")

        # 正则路径匹配
        for pattern in CONFIG["sensitive_paths"]:
            if pattern.search(path):
                return (True, f"路径匹配: {pattern.pattern}")

        # 多层压缩检测
        parts = path.split('.')
        if len(parts) > 2 and any(p in CONFIG["sensitive_ext"] for p in parts[-2:]):
            return (True, f"复合压缩文件: {'+'.join(parts[-2:])}")

        return (False, None)

    async def scan(self, url, depth=0):
        if self._shutdown or depth > CONFIG["max_depth"]:
            return

        try:
            processed_url = await self._process_url(url)
            if not processed_url:
                return

            # 敏感文件快速检测
            is_sensitive, reason = self._detect_sensitive(processed_url)
            if is_sensitive:
                self.findings["SENSITIVE_FILES"].append({
                    "url": processed_url,
                    "reason": reason
                })
                return

            async with self.concurrency_sem:
                async with self.session.get(
                        processed_url,
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=CONFIG["request_timeout"])
                ) as resp:
                    self.stats['success_requests'] += 1

                    # 仅解析首层HTML链接
                    if depth == 0 and 'text/html' in resp.headers.get('Content-Type', ''):
                        content = await resp.text()
                        soup = BeautifulSoup(content, 'lxml')
                        for tag in soup.select('a[href]'):
                            new_url = urljoin(processed_url, tag['href'])
                            await self._schedule_task(new_url, depth + 1)

        except Exception as e:
            self.stats['failed_requests'] += 1
            logging.debug(f"请求异常: {str(e)}")

    async def _schedule_task(self, url, depth):
        """任务调度管理"""
        if (not self._shutdown and
                depth <= CONFIG["max_depth"] and
                url not in self.dedup_filter):
            self.dedup_filter.add(url)
            task = asyncio.create_task(self.scan(url, depth))
            await asyncio.wait_for(task, timeout=CONFIG["request_timeout"])

    async def _log_progress(self):
        """实时进度显示"""
        while not self._shutdown:
            elapsed = time.time() - self.stats['start_time']
            sys.stdout.write(
                f"\r扫描进度 | 成功请求: {self.stats['success_requests']}次 | "
                f"敏感文件: {len(self.findings['SENSITIVE_FILES'])}个 | "
                f"运行时长: {elapsed:.1f}秒"
            )
            sys.stdout.flush()
            await asyncio.sleep(0.8)

    async def generate_reports(self):
        """生成中文报告"""
        filename = f"安全扫描报告_{time.strftime('%Y%m%d_%H%M')}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["风险等级", "URL地址", "检测依据"])

                for item in self.findings["SENSITIVE_FILES"]:
                    writer.writerow(["高危", item["url"], item["reason"]])

            logging.info(f"报告文件已生成: {os.path.abspath(filename)}")
            return filename
        except Exception as e:
            logging.error(f"报告生成失败: {str(e)}")
            return None

    async def run(self, targets):
        self.session = aiohttp.ClientSession(
            headers={"User-Agent": self.ua.random}
        )
        self.stats['start_time'] = time.time()
        progress_task = asyncio.create_task(self._log_progress())

        try:
            tasks = [self.scan(url) for url in {t.strip() for t in targets if t.strip()}]
            await asyncio.gather(*tasks)
        finally:
            progress_task.cancel()
            await self.session.close()

        report_path = await self.generate_reports()
        print(f"\n扫描完成，报告路径: {os.path.abspath(report_path)}")


# 修改主程序入口逻辑（新增交互模式）
if __name__ == "__main__":
    targets = []

    try:
        # 交互式输入处理
        if len(sys.argv) == 1:
            print("\n🛡️ index of/漏洞扫描器交互模式")
            print("----------------------------------------")
            filename = input("请输入目标文件路径: ").strip(' "\'')

            if not os.path.exists(filename):
                raise FileNotFoundError(f"文件不存在: {filename}")

            with open(filename) as f:
                targets = [line.strip() for line in f if line.strip()]

        elif len(sys.argv) == 2:
            with open(sys.argv[1]) as f:
                targets = [line.strip() for line in f if line.strip()]

        else:
            print("错误: 参数过多")
            print("用法: python scanner.py [目标文件]")
            sys.exit(1)

        # 启动扫描引擎
        print("\n🔍 正在初始化扫描引擎...")
        scanner = ScannerCore()
        asyncio.run(scanner.run(targets))

    except KeyboardInterrupt:
        print("\n⚠️ 用户主动终止扫描进程")
    except FileNotFoundError as e:
        print(f"\n‼️ 文件读取失败: {str(e)}")
        print("请检查文件路径是否正确")
    except Exception as e:
        print(f"\n‼️ 系统异常: {str(e)}")