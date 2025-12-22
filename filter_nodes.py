#!/usr/bin/env python3
"""
节点过滤脚本 - 简化版
只移除 http=、https=、socks5= 开头的节点
"""

import requests
import os

SOURCE_URL = "https://raw.githubusercontent.com/Graysongon/google/refs/heads/main/%E4%B8%AA%E4%BA%BA"
OUTPUT_FILE = "kejiland.txt"

def main():
    print("开始获取节点数据...")
    
    try:
        # 获取数据
        response = requests.get(SOURCE_URL, timeout=30)
        response.encoding = response.apparent_encoding or 'utf-8'
        content = response.text
        lines = content.splitlines()
        
        print(f"获取成功，共 {len(lines)} 行")
        
        # 过滤数据
        filtered_lines = []
        removed_count = 0
        
        for line in lines:
            line_stripped = line.strip()
            
            # 跳过空行
            if not line_stripped:
                filtered_lines.append(line)
                continue
            
            # 检查是否需要移除
            line_lower = line_stripped.lower()
            if (line_lower.startswith('http=') or 
                line_lower.startswith('https=') or 
                line_lower.startswith('socks5=')):
                removed_count += 1
                continue
            
            # 保留其他所有节点
            filtered_lines.append(line)
        
        print(f"过滤完成：移除 {removed_count} 行，保留 {len(filtered_lines)} 行")
        
        # 保存结果
        result = '\n'.join(filtered_lines)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(result)
        
        # 验证结果
        verify_count = 0
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line_stripped = line.strip().lower()
                if (line_stripped.startswith('http=') or 
                    line_stripped.startswith('https=') or 
                    line_stripped.startswith('socks5=')):
                    verify_count += 1
        
        if verify_count == 0:
            print(f"✅ 验证通过：无 HTTP/HTTPS/SOCKS5 节点")
        else:
            print(f"⚠️  警告：仍有 {verify_count} 个未过滤节点")
        
        print(f"结果已保存到 {OUTPUT_FILE}")
        return True
        
    except Exception as e:
        print(f"❌ 错误：{e}")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
