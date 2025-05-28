import streamlit as st
import pandas as pd
import io
from sql_analyzer import SQLAnalyzer

def main():
    st.set_page_config(
        page_title="SQL File Analyzer",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 SQL File Analyzer")
    st.markdown("Upload SQL files to analyze table usage, FROM clauses, and temporary tables")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        sql_dialect = st.selectbox(
            "SQL Dialect",
            ["auto", "postgresql", "mysql", "sqlite"],
            help="Select the SQL dialect for better parsing accuracy"
        )
        
        show_statistics = st.checkbox("Show Usage Statistics", value=True)
        show_dependencies = st.checkbox("Show Table Dependencies", value=True)
        debug_mode = st.checkbox("Debug Mode", value=False, help="Show detailed parsing information")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose SQL file(s)",
        type=['sql', 'txt'],
        accept_multiple_files=True,
        help="Upload one or more SQL files for analysis"
    )
    
    if uploaded_file:
        analyzer = SQLAnalyzer(dialect=sql_dialect if sql_dialect != "auto" else None)
        
        # Process each uploaded file
        for file in uploaded_file:
            st.header(f"📄 Analysis for: {file.name}")
            
            try:
                # Read file content
                content = file.read().decode('utf-8')
                
                # Analyze SQL content
                results = analyzer.analyze_sql(content, file.name)
                
                # Show debug information if enabled
                if debug_mode:
                    with st.expander(f"Debug Info for {file.name}"):
                        st.write("**Raw SQL Content (first 500 chars):**")
                        st.code(content[:500], language='sql')
                        st.write("**Parsed Statements:**")
                        statements = content.split(';')
                        for i, stmt in enumerate(statements, 1):
                            if stmt.strip():
                                st.write(f"Statement {i}: {stmt.strip()[:100]}...")
                        st.write("**Analysis Results:**")
                        st.json(results)
                
                if results['error']:
                    st.error(f"Error analyzing {file.name}: {results['error']}")
                    continue
                
                # Display results in tabs
                tab1, tab2, tab3, tab4 = st.tabs(["📊 Summary", "🏷️ Tables", "⏱️ Temporary Tables", "📈 Statistics"])
                
                with tab1:
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Total Statements", results['total_statements'])
                    with col2:
                        st.metric("Unique Tables", len(results['from_tables']))
                    with col3:
                        st.metric("Temporary Tables", len(results['temp_tables']))
                    with col4:
                        st.metric("CTEs Found", len(results['ctes']))
                
                with tab2:
                    st.subheader("Tables in FROM Clauses")
                    if results['from_tables']:
                        # Create DataFrame for better display
                        table_data = []
                        for table_name, occurrences in results['from_tables'].items():
                            table_data.append({
                                'Table Name': table_name,
                                'Occurrences': len(occurrences),
                                'First Appearance': f"Statement {min(occurrences)}"
                            })
                        
                        df_tables = pd.DataFrame(table_data)
                        st.dataframe(df_tables, use_container_width=True)
                        
                        # Show detailed occurrences
                        with st.expander("View Detailed Occurrences"):
                            for table_name, occurrences in results['from_tables'].items():
                                st.write(f"**{table_name}**: Statements {', '.join(map(str, occurrences))}")
                    else:
                        st.info("No tables found in FROM clauses")
                
                with tab3:
                    st.subheader("Temporary Tables and CTEs")
                    
                    if results['temp_tables'] or results['ctes']:
                        temp_data = []
                        
                        # Add temporary tables
                        for temp_table in results['temp_tables']:
                            temp_data.append({
                                'Name': temp_table['name'],
                                'Type': temp_table['type'],
                                'Statement': temp_table['statement_num'],
                                'Definition': temp_table['definition'][:100] + '...' if len(temp_table['definition']) > 100 else temp_table['definition']
                            })
                        
                        # Add CTEs
                        for cte in results['ctes']:
                            temp_data.append({
                                'Name': cte['name'],
                                'Type': 'CTE',
                                'Statement': cte['statement_num'],
                                'Definition': cte['definition'][:100] + '...' if len(cte['definition']) > 100 else cte['definition']
                            })
                        
                        if temp_data:
                            df_temp = pd.DataFrame(temp_data)
                            st.dataframe(df_temp, use_container_width=True)
                            
                            # Show full definitions
                            with st.expander("View Full Definitions"):
                                for item in results['temp_tables'] + results['ctes']:
                                    with st.container():
                                        st.write(f"**{item['name']}** ({item.get('type', 'CTE')})")
                                        st.code(item['definition'], language='sql')
                                        st.divider()
                    else:
                        st.info("No temporary tables or CTEs found")
                
                with tab4:
                    if show_statistics and results['from_tables']:
                        st.subheader("Table Usage Statistics")
                        
                        # Most used tables
                        usage_data = [(name, len(occurrences)) for name, occurrences in results['from_tables'].items()]
                        usage_data.sort(key=lambda x: x[1], reverse=True)
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write("**Most Used Tables**")
                            for name, count in usage_data[:10]:
                                st.write(f"• {name}: {count} times")
                        
                        with col2:
                            st.write("**Usage Distribution**")
                            df_usage = pd.DataFrame(usage_data, columns=['Table', 'Usage Count'])
                            st.bar_chart(df_usage.set_index('Table')['Usage Count'])
                        
                        # Table dependencies
                        if show_dependencies and results['dependencies']:
                            st.subheader("Table Dependencies")
                            for stmt_num, deps in results['dependencies'].items():
                                if deps:
                                    st.write(f"**Statement {stmt_num}**: {' → '.join(deps)}")
                    else:
                        st.info("No statistics available")
                
                # Export functionality
                st.subheader("📤 Export Results")
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button(f"Export {file.name} Results as CSV", key=f"csv_{file.name}"):
                        csv_data = analyzer.export_to_csv(results)
                        st.download_button(
                            label="Download CSV",
                            data=csv_data,
                            file_name=f"{file.name}_analysis.csv",
                            mime="text/csv"
                        )
                
                with col2:
                    if st.button(f"Export {file.name} Results as JSON", key=f"json_{file.name}"):
                        json_data = analyzer.export_to_json(results)
                        st.download_button(
                            label="Download JSON",
                            data=json_data,
                            file_name=f"{file.name}_analysis.json",
                            mime="application/json"
                        )
                
                st.divider()
                
            except Exception as e:
                st.error(f"Error processing {file.name}: {str(e)}")
                st.exception(e)
    
    else:
        # Show example and instructions
        st.info("👆 Upload SQL files to begin analysis")
        
        with st.expander("ℹ️ What this analyzer can detect"):
            st.markdown("""
            **Table References:**
            - Tables in FROM clauses
            - Tables in JOIN statements
            - Subquery table references
            
            **Temporary Tables:**
            - CREATE TEMP TABLE statements
            - CREATE TEMPORARY TABLE statements
            - Common Table Expressions (CTEs)
            - WITH clauses
            
            **Features:**
            - Multi-statement SQL file support
            - Case-insensitive parsing
            - Comment handling
            - Usage statistics and frequency analysis
            - Table dependency tracking
            - Export results to CSV/JSON
            """)
        
        with st.expander("📝 Example SQL File"):
            st.code("""
-- Example SQL with various table types
CREATE TEMP TABLE temp_sales AS
SELECT * FROM sales WHERE date > '2023-01-01';

WITH monthly_summary AS (
    SELECT 
        EXTRACT(month FROM date) as month,
        SUM(amount) as total
    FROM temp_sales ts
    JOIN customers c ON ts.customer_id = c.id
    GROUP BY month
)
SELECT * FROM monthly_summary;

CREATE TEMPORARY TABLE temp_report AS
SELECT 
    c.name,
    SUM(s.amount) as total_sales
FROM customers c
LEFT JOIN sales s ON c.id = s.customer_id
GROUP BY c.name;
            """, language='sql')

if __name__ == "__main__":
    main()
