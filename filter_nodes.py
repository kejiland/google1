#!/usr/bin/env python3
"""
GitHub 自动节点过滤器 - 精简版
功能：只移除 http=、https=、socks5= 开头的节点，保留其他所有节点
"""

import requests
import re
import os
from datetime import datetime
import logging

# 配置
SOURCE_URL = "https://raw.githubusercontent.com/Graysongon/google/refs/heads/main/%E4%B8%AA%E4%BA%BA"
OUTPUT_FILE = "kejiland.txt"
LOG_FILE = "filter.log"

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def fetch_nodes():
    """从源地址获取节点数据"""
    try:
        logger.info(f"📡 正在从源地址获取数据...")
        response = requests.get(SOURCE_URL, timeout=30)
        response.raise_for_status()
        
        # 检测编码
        response.encoding = response.apparent_encoding or 'utf-8'
        content = response.text
        
        lines = content.splitlines()
        logger.info(f"✅ 获取成功！共 {len(lines)} 行数据")
        return content
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ 获取数据失败: {e}")
        return None
    except Exception as e:
        logger.error(f"❌ 未知错误: {e}")
        return None

def filter_nodes(content):
    """
    过滤节点，只移除 http=、https=、socks5= 开头的行
    保留所有其他格式的节点
    """
    if not content:
        logger.error("内容为空，无法过滤")
        return None
    
    lines = content.splitlines()
    
    filtered_lines = []
    removed_count = 0
    preserved_count = 0
    
    # 要移除的协议列表（不区分大小写）
    remove_protocols = ['http=', 'https=', 'socks5=']
    
    logger.info("🔍 开始过滤节点...")
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        
        # 跳过空行
        if not line_stripped:
            filtered_lines.append(line)
            continue
        
        # 检查是否是需要移除的协议
        should_remove = False
        for protocol in remove_protocols:
            if line_stripped.lower().startswith(protocol):
                should_remove = True
                removed_count += 1
                
                # 记录前几个被过滤的节点
                if removed_count <= 3:
                    logger.debug(f"移除: {line_stripped[:60]}...")
                break
        
        if should_remove:
            continue
        
        # 保留所有其他节点
        filtered_lines.append(line)
        preserved_count += 1
    
    # 输出统计信息
    logger.info("=" * 60)
    logger.info("📊 过滤统计")
    logger.info("=" * 60)
    logger.info(f"📄 原始行数: {len(lines)}")
    logger.info(f"🗑️  移除节点: {removed_count} 个")
    logger.info(f"💾 保留节点: {preserved_count} 个")
    logger.info(f"📈 保留比例: {preserved_count/len(lines)*100:.1f}%")
    
    # 分析保留的节点类型
    analyze_preserved_nodes(filtered_lines)
    
    return '\n'.join(filtered_lines)

def analyze_preserved_nodes(lines):
    """分析保留的节点类型"""
    logger.info("📋 保留节点类型分析:")
    
    # 常见的节点协议模式
    protocol_patterns = {
        'ss': r'^\s*ss[:\=]',  # ss:// 或 ss=
        'vmess': r'^\s*vmess[:\=]',
        'vless': r'^\s*vless[:\=]',
        'trojan': r'^\s*trojan[:\=]',
        'ssr': r'^\s*ssr[:\=]',
        'hysteria': r'^\s*hysteria[:\=]',
        'tuic': r'^\s*tuic[:\=]',
        'wireguard': r'^\s*wireguard[:\=]',
        '其他': None  # 默认分类
    }
    
    stats = {key: 0 for key in protocol_patterns.keys()}
    stats['其他'] = 0
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue
            
        classified = False
        for protocol, pattern in protocol_patterns.items():
            if pattern and re.match(pattern, line_stripped, re.IGNORECASE):
                stats[protocol] += 1
                classified = True
                break
        
        if not classified and line_stripped:
            stats['其他'] += 1
    
    # 输出统计
    for protocol, count in stats.items():
        if count > 0:
            percentage = count/sum(stats.values())*100
            logger.info(f"  {protocol}: {count} 个 ({percentage:.1f}%)")
    
    # 显示保留的节点示例
    logger.info("\n📝 保留节点示例:")
    example_count = 0
    for line in lines:
        line_stripped = line.strip()
        if line_stripped and example_count < 5:
            # 提取协议部分
            match = re.match(r'^\s*([a-zA-Z0-9]+)[:\=]', line_stripped)
            if match:
                protocol = match.group(1)
                logger.info(f"  {protocol}: {line_stripped[:70]}...")
                example_count += 1

def verify_filtering(content):
    """验证过滤结果，确保没有 http/https/socks5 残留"""
    lines = content.splitlines()
    
    # 检查是否还有需要移除的协议
    remaining_problems = []
    remove_protocols = ['http=', 'https=', 'socks5=']
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue
            
        for protocol in remove_protocols:
            if line_stripped.lower().startswith(protocol):
                remaining_problems.append(line_stripped)
                break
    
    if not remaining_problems:
        logger.info("✅ 验证通过：无 HTTP/HTTPS/SOCKS5 节点残留")
        return True
    else:
        logger.warning(f"⚠️  发现 {len(remaining_problems)} 个未过滤的节点:")
        for problem in remaining_problems[:3]:  # 只显示前3个
            logger.warning(f"  - {problem[:60]}...")
        return False

def save_result(content):
    """保存过滤后的结果到文件"""
    try:
        # 检查是否与现有内容相同（避免不必要的写入）
        existing_content = ""
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                existing_content = f.read()
        
        if content == existing_content:
            logger.info("📌 内容无变化，无需更新文件")
            return False
        
        # 写入新内容
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
        
        file_size = os.path.getsize(OUTPUT_FILE)
        logger.info(f"✅ 结果已保存到 {OUTPUT_FILE}")
        logger.info(f"📏 文件大小: {file_size} 字节")
        logger.info(f"📄 文件行数: {len(content.splitlines())}")
        
        return True
    except Exception as e:
        logger.error(f"❌ 保存文件失败: {e}")
        return False

def main():
    """主函数"""
    logger.info("=" * 60)
    logger.info(f"🚀 GitHub 节点过滤器启动")
    logger.info(f"🕐 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 60)
    
    # 1. 获取数据
    raw_content = fetch_nodes()
    if not raw_content:
        logger.error("无法获取数据，程序终止")
        return False
    
    # 2. 过滤节点（只移除 http/https/socks5）
    filtered_content = filter_nodes(raw_content)
    if not filtered_content:
        logger.error("过滤失败")
        return False
    
    # 3. 验证过滤结果
    verify_filtering(filtered_content)
    
    # 4. 保存结果
    success = save_result(filtered_content)
    
    # 5. 最终统计
    logger.info("=" * 60)
    if success:
        logger.info("🎉 任务执行成功！新内容已保存")
    else:
        logger.info("📝 任务完成（无内容更新）")
    logger.info("=" * 60)
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)