import streamlit as st
from langchain_community.llms import Ollama
from streamlit_echarts import st_echarts
import re
import pandas as pd  # 新增

st.set_page_config(page_title="AI 流量哨兵", page_icon="🛡️")

# ========== 威胁类型配置（扩展只需修改这里） ==========
THREAT_LABELS = {
    "正常流量": "normal",
    "SQL注入": "sqli",
    "XSS攻击": "xss",
    "其他可疑": "other"
}

LABEL_ALIASES = {
    "正常": "正常流量",
    "无威胁": "正常流量",
    "安全": "正常流量",
    "SQL": "SQL注入",
    "注入": "SQL注入",
    "XSS": "XSS攻击",
    "跨站": "XSS攻击",
    "脚本攻击": "XSS攻击",
    "可疑": "其他可疑",
    "恶意": "其他可疑"
}

def init_risk_counts():
    return {key: 0 for key in THREAT_LABELS.keys()}

# ========== 初始化 session_state ==========
if "analysis_summary" not in st.session_state:
    st.session_state.analysis_summary = []
if "risk_counts" not in st.session_state:
    st.session_state.risk_counts = init_risk_counts()
if "last_analysis_result" not in st.session_state:
    st.session_state.last_analysis_result = None

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
    "📁 上传流量日志 (支持批量，可多选 TXT)",
    type="txt",
    accept_multiple_files=True
)

if uploaded_files:
    if len(uploaded_files) > 1:
        file_names = [f.name for f in uploaded_files]
        st.info(f"📋 已选择 {len(uploaded_files)} 个文件：{', '.join(file_names)}")

    with st.expander("📄 点击展开第一个文件内容预览"):
        first_file = uploaded_files[0]
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
            string_data = uploaded_file.read().decode("utf-8")
            content_for_ai = string_data[:2000]

            with st.spinner(f"RTX 4060 推理中: {uploaded_file.name}"):
                prompt = f"""
                你是一个网络安全专家。请分析以下 HTTP 流量日志片段。

                **重要要求**：
                请在回答的**第一行**，用半角方括号列出检测到的所有威胁类型，多个类型用逗号分隔。
                可选类型：正常流量, SQL注入, XSS攻击, 其他可疑

                **关键约束**：
                - 只标记日志中**确实出现**的攻击特征，不要根据经验或可能性进行推测。
                - 例如：如果日志中只包含 `<script>` 标签而无 SQL 语句，则**只能**标记 `[XSS攻击]`，绝对不要同时标记 `[SQL注入]`。

                格式示例：
                [正常流量]
                [SQL注入, XSS攻击]
                [其他可疑]

                然后从第二行开始，用中文详细解释分析理由。

                流量日志如下：
                {content_for_ai}
                """
                response = llm.invoke(prompt)

            labels = parse_threat_labels(response)
            st.write(f"**{uploaded_file.name}** 检测标签: {labels}")
            update_risk_counts(response)

            # 收集汇总记录
            explanation = response.split('\n', 1)[1] if len(response.split('\n', 1)) > 1 else response
            brief = explanation[:150] + "..." if len(explanation) > 150 else explanation
            summary_item = {
                "文件名": uploaded_file.name,
                "检测结果": ", ".join(labels),
                "简要解释": brief
            }
            st.session_state.analysis_summary.append(summary_item)

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
    except Exception as e:
        st.error(f"表格生成失败: {e}")
        st.write("原始数据:", st.session_state.analysis_summary)
# =====================================================

# 显示上次分析结果
if st.session_state.last_analysis_result is not None:
    st.subheader("🤖 AI 分析结果（最后一个文件）")
    st.success("分析完成！")
    lines = st.session_state.last_analysis_result.split('\n', 1)
    if len(lines) > 1:
        st.write(lines[1])
    else:
        st.write(st.session_state.last_analysis_result)
    st.info("💡 提示：侧边栏饼图已根据本次分析结果自动更新。")