import streamlit as st
from langchain_community.llms import Ollama
from streamlit_echarts import st_echarts  # 新增导入

st.set_page_config(page_title="AI 流量哨兵", page_icon="🛡️")

st.title("🛡️ 本地 AI 流量哨兵 (RTX 4060 加速版)")

# ========== 侧边栏：仪表盘可视化 ==========
st.sidebar.header("📊 风险等级分布（模拟）")
# 模拟数据，实际项目中可根据 AI 输出动态调整
risk_data = [
    {"value": 65, "name": "正常流量"},
    {"value": 20, "name": "可疑行为"},
    {"value": 10, "name": "SQL 注入"},
    {"value": 5, "name": "XSS 攻击"},
]
options = {
    "tooltip": {"trigger": "item"},
    "legend": {"orient": "vertical", "left": "left"},
    "series": [
        {
            "name": "流量分类",
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
        }
    ],
}
st_echarts(options=options, height="300px")
st.sidebar.markdown("---")


# ========== 主界面：AI 分析功能 ==========
@st.cache_resource
def load_llm():
    return Ollama(model="qwen2.5:7b", temperature=0.1)


llm = load_llm()

uploaded_file = st.file_uploader("📁 上传从 Kali 抓取的流量日志 (TXT)", type="txt")

if uploaded_file is not None:
    string_data = uploaded_file.read().decode("utf-8")
    content_for_ai = string_data[:2000]  # 防止超出模型上下文

    st.subheader("📄 抓包数据预览")
    st.text(content_for_ai)

    if st.button("🚀 启动 AI 安全分析"):
        with st.spinner("RTX 4060 正在推理中，请稍候..."):
            prompt = f"""
            你是一个网络安全专家。请分析以下 HTTP 流量日志片段，并完成两个任务：
            1. 识别出其中 2-3 个潜在的安全风险（如 SQL 注入、XSS、可疑 UA 等）。
            2. 用通俗易懂的中文简要解释这些风险。

            流量日志如下：
            {content_for_ai}
            """
            response = llm.invoke(prompt)

        st.subheader("🤖 AI 分析结果")
        st.success("分析完成！")
        st.write(response)

        st.info("💡 提示：以上分析由本地 RTX 4060 GPU 推理生成，数据未上传至云端。")
else:
    st.info("👆 请上传一个流量日志文件开始分析。")