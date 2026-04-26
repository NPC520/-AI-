import streamlit as st
from langchain_community.llms import Ollama
from streamlit_echarts import st_echarts
import re
import pandas as pd  # 新增
from scapy.all import rdpcap, TCP, IP, UDP  # 新增用于解析PCAP文件
from prompts import THREAT_LABELS, LABEL_ALIASES, ANALYSIS_PROMPT, init_risk_counts  # 新增：从prompts模块导入

st.set_page_config(page_title="AI 流量哨兵", page_icon="🛡️")

# ========== 配置已移至 prompts.py 文件 ==========

def parse_pcap(file_content):
    """解析PCAP文件并提取HTTP流量"""
    try:
        # 保存上传的PCAP文件到临时位置
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_file:
            temp_file.write(file_content.getvalue())
            temp_path = temp_file.name
        
        # 使用scapy读取PCAP文件
        packets = rdpcap(temp_path)
        
        # 清理临时文件
        os.unlink(temp_path)
        
        http_traffic = []
        for packet in packets:
            if packet.haslayer(TCP):
                payload = bytes(packet[TCP].payload)
                if payload:
                    # 尝试解码为字符串
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        # 检查是否包含HTTP方法
                        if any(method in payload_str[:10] for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']):
                            http_traffic.append(payload_str)
                    except:
                        pass
        
        return '\n\n'.join(http_traffic[:20])  # 最多返回20个HTTP包
    except Exception as e:
        return f"PCAP解析错误: {str(e)}"

# ========== 初始化 session_state ==========
if "analysis_summary" not in st.session_state:
    st.session_state.analysis_summary = []
if "risk_counts" not in st.session_state:
    st.session_state.risk_counts = init_risk_counts()
if "last_analysis_result" not in st.session_state:
    st.session_state.last_analysis_result = None
if "all_analysis_results" not in st.session_state:
    st.session_state.all_analysis_results = []  # 新增：保存所有文件的完整分析结果

def parse_threat_labels(ai_response):
    first_line = ai_response.strip().split('\n')[0]
    match = re.search(r'[\[【](.+?)[\]】]', first_line)
    if not match:
        return ["其他可疑"]
    labels_str = match.group(1).strip()
    raw_labels = [lbl.strip() for lbl in re.split(r'[,，]', labels_str) if lbl.strip()]
    normalized = []
    for raw in raw_labels:
        if raw in THREAT_LABELS:
            normalized.append(raw)
        else:
            mapped = LABEL_ALIASES.get(raw)
            if mapped:
                normalized.append(mapped)
            else:
                if any(kw in raw for kw in ["SQL", "注入"]):
                    normalized.append("SQL注入")
                elif any(kw in raw for kw in ["XSS", "跨站", "脚本"]):
                    normalized.append("XSS攻击")
                elif any(kw in raw for kw in ["正常", "无威胁", "安全"]):
                    normalized.append("正常流量")
                else:
                    normalized.append("其他可疑")
    return list(set(normalized))

def parse_confidence_scores(ai_response):
    """解析AI响应中的置信度评分"""
    lines = ai_response.strip().split('\n')
    if len(lines) < 2:
        return {}
    
    second_line = lines[1].strip()
    if '置信度:' in second_line:
        scores_str = second_line.split('置信度:')[1].strip()
        scores = {}
        for item in scores_str.split(','):
            item = item.strip()
            if '=' in item:
                parts = item.split('=')
                if len(parts) == 2:
                    label = parts[0].strip()
                    try:
                        score = int(parts[1].strip())
                        scores[label] = score
                    except:
                        pass
        return scores
    return {}

def update_risk_counts(ai_response):
    labels = parse_threat_labels(ai_response)
    for label in labels:
        if label in st.session_state.risk_counts:
            st.session_state.risk_counts[label] += 1
        else:
            st.session_state.risk_counts["其他可疑"] += 1

def get_risk_data():
    counts = st.session_state.risk_counts
    return [{"value": counts[label], "name": label} for label in THREAT_LABELS.keys()]

# ========== 侧边栏 ==========
st.sidebar.header("📊 累计风险统计（动态）")
risk_data = get_risk_data()
options = {
    "tooltip": {"trigger": "item"},
    "legend": {"orient": "vertical", "left": "left"},
    "series": [{
        "name": "检测统计",
        "type": "pie",
        "radius": "50%",
        "data": risk_data,
        "emphasis": {
            "itemStyle": {
                "shadowBlur": 10,
                "shadowOffsetX": 0,
                "shadowColor": "rgba(0, 0, 0, 0.5)",
            }
        },
    }],
}
st_echarts(options=options, height="300px")

if st.sidebar.button("🔄 重置统计数据"):
    st.session_state.risk_counts = init_risk_counts()
    st.session_state.last_analysis_result = None
    st.sidebar.success("统计已重置")
    st.rerun()

if st.sidebar.button("🧹 清空汇总记录"):
    st.session_state.analysis_summary = []
    st.sidebar.success("汇总记录已清空")
    st.rerun()

if st.session_state.last_analysis_result is not None:
    st.sidebar.markdown("---")
    st.sidebar.caption("📝 最近分析结果预览（调试）")
    preview = st.session_state.last_analysis_result[:200] + "..."
    st.sidebar.text(preview)

st.sidebar.markdown("---")

# ========== 主界面 ==========
@st.cache_resource
def load_llm():
    return Ollama(model="qwen2.5:7b", temperature=0.1)

llm = load_llm()

uploaded_files = st.file_uploader(
    "📁 上传流量日志 (支持批量，可多选 TXT/PCAP)",
    type=["txt", "pcap"],
    accept_multiple_files=True
)

if uploaded_files:
    if len(uploaded_files) > 1:
        file_names = [f.name for f in uploaded_files]
        st.info(f"📋 已选择 {len(uploaded_files)} 个文件：{', '.join(file_names)}")

    with st.expander("📄 点击展开第一个文件内容预览"):
        first_file = uploaded_files[0]
        if first_file.name.lower().endswith('.pcap'):
            # 解析PCAP文件
            preview_content = parse_pcap(first_file)
            st.text(preview_content[:1000] + ("..." if len(preview_content) > 1000 else ""))
        else:
            # 处理TXT文件
            string_data = first_file.read().decode("utf-8")
            st.text(string_data[:1000] + ("..." if len(string_data) > 1000 else ""))
        first_file.seek(0)

    if st.button("🚀 启动 AI 安全分析 (批量处理)"):
        st.session_state.analysis_summary = []  # 清空上一次的汇总记录
        progress_bar = st.progress(0, text="准备分析...")
        total = len(uploaded_files)

        for idx, uploaded_file in enumerate(uploaded_files):
            progress_bar.progress(
                (idx) / total,
                text=f"正在分析第 {idx + 1}/{total} 个文件: {uploaded_file.name}"
            )
            
            # 根据文件类型处理
            if uploaded_file.name.lower().endswith('.pcap'):
                # 解析PCAP文件
                content_for_ai = parse_pcap(uploaded_file)
            else:
                # 处理TXT文件
                string_data = uploaded_file.read().decode("utf-8")
                content_for_ai = string_data[:2000]

            with st.spinner(f"RTX 4060 推理中: {uploaded_file.name}"):
                # 使用从prompts模块导入的提示词
                prompt = ANALYSIS_PROMPT.format(content_for_ai=content_for_ai)
                response = llm.invoke(prompt)

            labels = parse_threat_labels(response)
            scores = parse_confidence_scores(response)
            st.write(f"**{uploaded_file.name}** 检测标签: {labels}")
            if scores:
                st.write(f"**置信度评分**: {scores}")
            update_risk_counts(response)

            # 收集汇总记录
            explanation = response.split('\n', 2)[2] if len(response.split('\n', 2)) > 2 else response
            brief = explanation[:150] + "..." if len(explanation) > 150 else explanation
            
            # 格式化置信度评分
            scores_str = ", ".join([f"{k}={v}" for k, v in scores.items()]) if scores else "无"
            
            summary_item = {
                "文件名": uploaded_file.name,
                "检测结果": ", ".join(labels),
                "置信度评分": scores_str,
                "简要解释": brief
            }
            st.session_state.analysis_summary.append(summary_item)

            # 保存所有文件的完整分析结果
            st.session_state.all_analysis_results.append({
                "filename": uploaded_file.name,
                "result": response
            })
            
            if idx == total - 1:
                st.session_state.last_analysis_result = response

        progress_bar.progress(1.0, text="✅ 批量分析完成！")
        st.success(f"已完成 {total} 个文件的批量分析，侧边栏统计已更新。")

        st.rerun()

else:
    st.info("👆 请上传一个或多个流量日志文件开始分析。")
# ========== 新增：始终展示汇总表格（如果有数据） ==========
if st.session_state.analysis_summary:
    st.subheader("📋 批量分析结果汇总")
    try:
        df = pd.DataFrame(st.session_state.analysis_summary)
        st.table(df)
        
        # 导出功能
        st.subheader("💾 导出分析报告")
        col1, col2 = st.columns(2)
        
        with col1:
            # 导出为CSV
            csv = df.to_csv(index=False, encoding='utf-8-sig')
            st.download_button(
                label="📄 导出为 CSV",
                data=csv,
                file_name=f"ai_sentinel_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        with col2:
            # 导出为HTML
            html = df.to_html(index=False)
            timestamp_str = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
            file_count = len(st.session_state.analysis_summary)
            risk_stats = str(st.session_state.risk_counts)
            
            html_report = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 流量哨兵分析报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .summary {{ margin-top: 20px; padding: 10px; background-color: #f0f0f0; }}
    </style>
</head>
<body>
    <h1>AI 流量哨兵 - 分析报告</h1>
    <div class="summary">
        <p>生成时间: {timestamp_str}</p>
        <p>分析文件数: {file_count}</p>
        <p>威胁统计: {risk_stats}</p>
    </div>
    {html}
</body>
</html>
            """
            st.download_button(
                label="🌐 导出为 HTML",
                data=html_report,
                file_name=f"ai_sentinel_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html"
            )
    except Exception as e:
        st.error(f"表格生成失败: {e}")
        st.write("原始数据:", st.session_state.analysis_summary)
# =====================================================

# 显示分析结果选择器
if st.session_state.all_analysis_results:
    st.subheader("🤖 AI 分析结果")
    
    # 文件选择器
    file_options = [item["filename"] for item in st.session_state.all_analysis_results]
    selected_file = st.selectbox(
        "选择要查看的文件分析结果：",
        options=file_options,
        index=len(file_options)-1  # 默认显示最后一个文件
    )
    
    # 显示选中文件的分析结果
    for item in st.session_state.all_analysis_results:
        if item["filename"] == selected_file:
            st.success("分析完成！")
            lines = item["result"].split('\n', 2)
            if len(lines) > 2:
                st.write(lines[0])  # 显示标签
                st.write(lines[1])  # 显示置信度评分
                st.write(lines[2])  # 显示详细解释
            elif len(lines) > 1:
                st.write(lines[0])
                st.write(lines[1])
            else:
                st.write(item["result"])
            break
    st.info("💡 提示：侧边栏饼图已根据本次分析结果自动更新。")
elif st.session_state.last_analysis_result is not None:
    # 兼容旧的显示方式
    st.subheader("🤖 AI 分析结果（最后一个文件）")
    st.success("分析完成！")
    lines = st.session_state.last_analysis_result.split('\n', 2)
    if len(lines) > 2:
        st.write(lines[0])  # 显示标签
        st.write(lines[1])  # 显示置信度评分
        st.write(lines[2])  # 显示详细解释
    elif len(lines) > 1:
        st.write(lines[0])
        st.write(lines[1])
    else:
        st.write(st.session_state.last_analysis_result)
    st.info("💡 提示：侧边栏饼图已根据本次分析结果自动更新。")