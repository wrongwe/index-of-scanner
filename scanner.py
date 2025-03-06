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
from typing import Set, Tuple, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor

from bs4 import BeautifulSoup
from pybloom_live import ScalableBloomFilter
from fake_useragent import UserAgent
import logging

# 深度递归保护
sys.setrecursionlimit(10000)

# 军工级扫描配置
CONFIG = {
    "max_depth": 3,
    "request_timeout": 35,
    "concurrency_range": (50, 200),
    "forbidden_ports": {22, 3306, 3389},
    "sensitive_ext": {
        'config', 'ini', 'env', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
        'bak', 'key', 'conf', 'properties', 'sql', 'db', 'dbf', 'pem', 'crt',
        'jks', 'p12', 'audit', 'dmg', 'iso', 'img', 'vmdk', 'apk', 'jar'
    },
    "sensitive_paths": [
        re.compile(r'/(backup|archive)/', re.I),
        re.compile(r'\.(git|svn)/', re.I)
    ],
    "ignore_ext": {'png', 'jpg', 'jpeg', 'gif'}
}

# 企业级日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("scan_pro.log", mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)


class ScannerPro:
    def __init__(self):
        """初始化扫描引擎"""
        self.dedup_filter = ScalableBloomFilter(initial_capacity=100000, error_rate=0.001)
        self.ua = UserAgent()
        self.stats = defaultdict(int)
        self.findings = defaultdict(list)
        self.blocked_domains: Set[str] = set()
        self.active_tasks: Dict[str, Set[asyncio.Task]] = defaultdict(set)
        self.concurrency_ctrl = asyncio.Semaphore(CONFIG["concurrency_range"][1])
        self._shutdown = False
        self.session = None
        self.scanned_domains: Set[str] = set()  # 新增：用于记录已扫描的域名
        signal.signal(signal.SIGINT, self._graceful_shutdown)

    async def _scan_worker(self, url: str, depth: int = 0):
        """闪电级响应终止的扫描线程"""
        if self._shutdown:
            raise asyncio.CancelledError("主动终止")

        try:
            normalized_url = await self._normalize_url(url)
            parsed = urlparse(normalized_url)
            full_domain = parsed.netloc

            if full_domain in self.blocked_domains:
                return

            # 新增：记录已扫描的域名
            self.scanned_domains.add(full_domain)

            is_sensitive, reason = self._is_sensitive(normalized_url)
            if is_sensitive:
                self.findings["critical"].append({
                    "url": normalized_url,
                    "reason": reason
                })
                self.blocked_domains.add(full_domain)
                logging.critical(f"🚨 发现敏感文件阻断域名 [{full_domain}]")
                await self._cancel_domain_tasks(full_domain)
                return

            async with self.concurrency_ctrl:
                async with self.session.get(
                        normalized_url,
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=CONFIG["request_timeout"])
                ) as resp:
                    self.stats['total_requests'] += 1

                    if depth == 0 and 'text/html' in resp.headers.get('Content-Type', ''):
                        content = await resp.text()
                        soup = BeautifulSoup(content, 'lxml')
                        links = [urljoin(normalized_url, tag['href']) for tag in soup.select('a[href]')]
                        await self._schedule_tasks(links, depth + 1)

        except (aiohttp.ClientError, asyncio.CancelledError) as e:
            if isinstance(e, asyncio.CancelledError):
                raise  # 直接重新抛出保证快速终止
            self.stats['failed_requests'] += 1
            logging.debug(f"请求异常: {str(e)}")
        except Exception as e:
            self.stats['failed_requests'] += 1
            logging.error(f"未知错误: {str(e)}")

    async def run(self, targets: list):
        """闪电级响应运行入口"""
        try:
            async with aiohttp.ClientSession(
                    headers={"User-Agent": self.ua.random},
                    connector=aiohttp.TCPConnector(
                        ssl=False,
                        limit=200,
                        limit_per_host=20
                    )
            ) as self.session:
                monitor_task = asyncio.create_task(self._progress_monitor())
                main_task = asyncio.create_task(self._schedule_tasks(targets, 0))

                try:
                    await asyncio.wait_for(main_task, timeout=3600)
                except (asyncio.CancelledError, KeyboardInterrupt, asyncio.TimeoutError):
                    self._shutdown = True
                    logging.warning("正在紧急终止扫描进程...")

                    # 闪电级终止策略
                    all_tasks = {t for tasks in self.active_tasks.values() for t in tasks}
                    for task in all_tasks:
                        task.cancel()

                    # 极速等待（最多2秒）
                    await asyncio.wait(
                        all_tasks,
                        timeout=min(2.0, len(all_tasks) * 0.01),
                        return_when=asyncio.ALL_COMPLETED
                    )
                finally:
                    monitor_task.cancel()
                    try:
                        await monitor_task
                    except asyncio.CancelledError:
                        pass

                    # 最终清理
                    await self.session.close()

                # 立即生成报告
                report_file = await self.generate_report()
                print(f"\n🔚 扫描终止 | 报告文件: {os.path.abspath(report_file)}")
                # 新增：输出已扫描的域名数目
                print(f"已扫描的域名数目: {len(self.scanned_domains)}")
        except Exception as e:
            logging.error(f"Session异常: {str(e)}")
            raise

    def _graceful_shutdown(self, signum, frame):
        """优雅关闭处理"""
        logging.warning("接收到终止信号，正在保存扫描状态...")
        self._shutdown = True

    async def _normalize_url(self, raw_url: str) -> str:
        """URL标准化处理（军工级）"""
        url = raw_url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        parsed = urlparse(url)
        if parsed.port in CONFIG["forbidden_ports"]:
            raise ValueError(f"禁止访问高危端口: {parsed.geturl()}")

        full_domain = parsed.netloc
        if full_domain in self.blocked_domains:
            raise ValueError(f"域名已被阻断: {full_domain}")

        # 参数净化处理
        query = parse_qs(parsed.query)
        clean_query = '&'.join(
            f"{k}={v[0]}" for k, v in query.items()
            if not k.startswith(('utm_', 'token', 'auth'))
        )
        return urlunparse((
            parsed.scheme, full_domain, parsed.path.rstrip('/'),
            parsed.params, clean_query, parsed.fragment
        ))

    def _is_sensitive(self, url: str) -> Tuple[bool, str]:
        """智能敏感资源检测"""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # 多级扩展名检测
        if '.' in path:
            parts = path.split('.')
            combined_ext = '.'.join(parts[-2:])
            if combined_ext in {'tar.gz', 'tar.bz2', 'tar.xz'}:
                return True, f"复合压缩格式: {combined_ext}"

        # 扩展名检测
        if (ext := path.split('.')[-1]) in CONFIG["sensitive_ext"]:
            return True, f"敏感扩展名: {ext}"

        # 路径正则匹配
        for pattern in CONFIG["sensitive_paths"]:
            if pattern.search(path):
                return True, f"路径匹配: {pattern.pattern}"

        return False, None

    async def _schedule_tasks(self, urls: list, depth: int):
        """增强版任务调度"""
        tasks = []
        for url in {u for u in urls if u}:
            parsed = urlparse(url)
            domain = parsed.netloc

            if domain in self.blocked_domains or url in self.dedup_filter:
                continue

            self.dedup_filter.add(url)
            task = asyncio.create_task(
                self._scan_worker(url, depth),
                name=f"ScanWorker:{domain}"
            )

            # 添加安全回调
            def safe_remove(t):
                try:
                    self.active_tasks[domain].remove(t)
                except KeyError:
                    pass

            self.active_tasks[domain].add(task)
            task.add_done_callback(safe_remove)
            tasks.append(task)

        if tasks:
            try:
                await asyncio.wait_for(
                    asyncio.shield(asyncio.gather(*tasks, return_exceptions=True)),
                    timeout=CONFIG["request_timeout"] * 2
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    async def _cancel_domain_tasks(self, domain: str):
        """原子级任务终止方案"""
        if domain not in self.active_tasks:
            return

        cancel_tasks = self.active_tasks.pop(domain)
        if not cancel_tasks:
            return

        logging.info(f"🛑 终止任务组 [{domain}] 数量:{len(cancel_tasks)}")

        # 批量闪电取消
        for task in cancel_tasks:
            if not task.done():
                task.cancel()

        # 极速等待（最多500ms）
        done, pending = await asyncio.wait(
            cancel_tasks,
            timeout=min(0.5, len(cancel_tasks) * 0.001),
            return_when=asyncio.ALL_COMPLETED
        )

    def _emergency_cancel(self, task: asyncio.Task):
        """毫秒级任务终止"""
        try:
            task.cancel()
            if sys.platform == 'win32':
                with ThreadPoolExecutor(max_workers=1) as executor:
                    executor.submit(task.exception, timeout=0.1)
        except:
            pass

    async def _progress_monitor(self):
        """实时性能监控"""
        start = time.time()
        while not self._shutdown:
            elapsed = time.time() - start
            sys.stdout.write(
                f"\r🚀 扫描中 | 成功: {self.stats['total_requests']} | "
                f"阻断: {len(self.blocked_domains)} | "
                f"高危: {len(self.findings['critical'])} | "
                f"耗时: {elapsed:.1f}s"
            )
            sys.stdout.flush()
            await asyncio.sleep(0.5)

    async def generate_report(self):
        """生成精简报告"""
        filename = f"安全审计报告_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["风险等级", "URL地址", "检测依据"])
                for item in self.findings["critical"]:
                    writer.writerow(["严重", item["url"], item["reason"]])
            logging.info(f"报告路径: {os.path.abspath(filename)}")
            return filename
        except Exception as e:
            logging.error(f"报告生成失败: {str(e)}")
            return None

if __name__ == "__main__":
    targets = []
    try:
        if len(sys.argv) == 1:
            print("\n🔐 index of/安全扫描系统 v2.3")
            print("━" * 40)
            input_file = input("请输入目标文件路径: ").strip(' "\'')
            if not os.path.exists(input_file):
                raise FileNotFoundError(f"文件不存在: {input_file}")
            with open(input_file, encoding='utf-8') as f:
                targets = [ln.strip() for ln in f if ln.strip()]

        elif len(sys.argv) == 2:
            with open(sys.argv[1], encoding='utf-8') as f:
                targets = [ln.strip() for ln in f if ln.strip()]

        else:
            print("参数错误")
            print("用法: python scanner_pro.py [目标文件]")
            sys.exit(1)

        engine = ScannerPro()
        asyncio.run(engine.run(targets))

    except KeyboardInterrupt:
        print("\n⚠️ 用户中断操作")
    except FileNotFoundError as e:
        print(f"\n❌ 文件错误: {str(e)}")
    except Exception as e:
        print(f"\n‼️ 系统异常: {str(e)}")
        logging.exception("致命错误")