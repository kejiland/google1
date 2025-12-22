#!/usr/bin/env python3
"""
GitHub 自动节点过滤器 - 修正版
功能：只移除 http=、https=、socks5= 开头的节点
保留所有标准代理节点格式
"""

import requests
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
        
        response.encoding = response.apparent_encoding or 'utf-8'
        content = response.text
        lines = content.splitlines()
        
        logger.info(f"✅ 获取成功！共 {len(lines)} 行数据")
        
        # 显示数据格式分析
        logger.info("📋 数据格式分析:")
        protocols = {}
        for line in lines:
            if line.strip():
                # 提取协议部分
                if '://' in line:
                    protocol = line.split('://')[0].lower()
                elif '=' in line:
                    protocol = line.split('=')[0].strip().lower()
                else:
                    continue
                
                protocols[protocol] = protocols.get(protocol, 0) + 1
        
        for protocol, count in sorted(protocols.items()):
            logger.info(f"  {protocol}: {count} 个")
        
        return content
    except Exception as e:
        logger.error(f"❌ 获取数据失败: {e}")
        return None

def filter_nodes(content):
    """过滤节点，只移除 http=、https=、socks5= 开头的行"""
    if not content:
        return None
    
    lines = content.splitlines()
    filtered_lines = []
    removed_count = 0
    
    # 要移除的协议（只有这三种格式使用 =）
    remove_protocols = ['http=', 'https=', 'socks5=']
    
    logger.info("🔍 开始过滤节点...")
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        
        if not line_stripped:
            filtered_lines.append(line)
            continue
        
        # 检查是否是需要移除的协议（使用 = 格式）
        should_remove = False
        for protocol in remove_protocols:
            if line_stripped.lower().startswith(protocol):
                should_remove = True
                removed_count += 1
                
                if removed_count <= 3:  # 只显示前3个被过滤的
                    logger.debug(f"移除 {protocol}: {line_stripped[:60]}...")
                break
        
        if should_remove:
            continue
        
        # 保留所有其他行（包括标准格式 ss://, vmess:// 等）
        filtered_lines.append(line)
    
    logger.info(f"📊 过滤统计:")
    logger.info(f"  原始行数: {len(lines)}")
    logger.info(f"  移除行数: {removed_count} (http=/https=/socks5=)")
    logger.info(f"  保留行数: {len(filtered_lines)}")
    
    # 分析保留的节点格式
    analyze_preserved_nodes(filtered_lines)
    
    return '\n'.join(filtered_lines)

def analyze_preserved_nodes(lines):
    """分析保留的节点类型"""
    standard_protocols = {
        'ss://': 0,
        'vmess://': 0,
        'vless://': 0,
        'trojan://': 0,
        'ssr://': 0,
        '其他格式': 0
    }
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue
        
        line_lower = line_stripped.lower()
        
        # 检查标准格式
        found = False
        for protocol in standard_protocols:
            if line_lower.startswith(protocol):
                standard_protocols[protocol] += 1
                found = True
                break
        
        if not found:
            standard_protocols['其他格式'] += 1
    
    logger.info("📋 保留节点格式分析:")
    total_preserved = sum(standard_protocols.values())
    for protocol, count in standard_protocols.items():
        if count > 0:
            percentage = count / total_preserved * 100 if total_preserved > 0 else 0
            logger.info(f"  {protocol}: {count} 个 ({percentage:.1f}%)")
    
    # 显示保留的节点示例
    logger.info("📝 保留节点示例 (前5个):")
    example_count = 0
    for line in lines:
        line_stripped = line.strip()
        if line_stripped and example_count < 5:
            logger.info(f"  {line_stripped[:80]}...")
            example_count += 1

def save_result(content):
    """保存过滤后的结果到文件"""
    try:
        # 检查是否与现有内容相同
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

def verify_result():
    """验证过滤结果"""
    try:
        if not os.path.exists(OUTPUT_FILE):
            logger.error("输出文件不存在")
            return False
        
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.splitlines()
        
        # 检查是否还有需要移除的内容
        bad_lines = []
        for line in lines:
            line_stripped = line.strip()
            if line_stripped:
                line_lower = line_stripped.lower()
                if (line_lower.startswith('http=') or 
                    line_lower.startswith('https=') or 
                    line_lower.startswith('socks5=')):
                    bad_lines.append(line)
        
        if not bad_lines:
            logger.info("✅ 验证通过：无 http=/https=/socks5= 节点")
            return True
        else:
            logger.warning(f"⚠️  发现 {len(bad_lines)} 个未过滤的节点:")
            for bad_line in bad_lines[:3]:  # 只显示前3个
                logger.warning(f"  - {bad_line[:60]}...")
            return False
            
    except Exception as e:
        logger.error(f"验证失败: {e}")
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
    
    # 2. 过滤节点
    filtered_content = filter_nodes(raw_content)
    if not filtered_content:
        logger.error("过滤失败")
        return False
    
    # 3. 保存结果
    if not save_result(filtered_content):
        logger.info("没有新内容更新")
    
    # 4. 验证结果
    verify_result()
    
    logger.info("=" * 60)
    logger.info("🎉 任务执行完成")
    logger.info("=" * 60)
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
