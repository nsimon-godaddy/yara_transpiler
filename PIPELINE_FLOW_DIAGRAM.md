### **File Type Detection:**
```
Input File
    │
    ├─ .txt extension? ──▶ YES ──▶ JSON Conversion Path
    │                           │
    │                           ▼
    │                    ┌─────────────┐
    │                    │ txt_to_json │
    │                    │   .py       │
    │                    └─────────────┘
    │                           │
    │                           ▼
    │                    ┌─────────────┐
    │                    │ signatures  │
    │                    │   .json     │
    │                    └─────────────┘
    │                           │
    │                           ▼
    │                    ┌─────────────┐
    │                    │ transpile   │
    │                    │   to_yara   │
    │                    │    .py      │
    │                    └─────────────┘
    │                           │
    │                           ▼
    │                    ┌─────────────┐
    │                    │ YARA Rules  │
    │                    └─────────────┘
    │
    └─ .txt extension? ──▶ NO ──▶ Direct LLM Analysis Path
                                │
                                ▼
                        ┌─────────────┐
                        │ data_class  │
                        │   .py       │
                        └─────────────┘
                                │
                                ▼
                        ┌─────────────┐
                        │ LLM Output  │
                        │ Analysis    │
                        └─────────────┘
                                │
                                ▼
                        ┌─────────────┐
                        │ YARA Rule   │
                        │ Extraction  │
                        └─────────────┘
                                │
                                ▼
                        ┌─────────────┐
                        │ YARA Rules  │
                        └─────────────┘
```
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VALIDATION LAYER                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ • Both paths converge here for quality assurance        │   │
│  │ • LLM validation of all generated YARA rules            │   │
│  │ • Quality feedback and improvement suggestions           │   │
│  │ • Performance analysis and rule effectiveness            │   │
│  │ • Output: validation_results_*.json                     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FINAL OUTPUT                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ • Combined YARA rules from both processing paths        │   │
│  │ • Validated and quality-assured rules                   │   │
│  │ • Ready for production use                              │   │
│  │ • Clean data folder with only final results             │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘



## 🔄 **Data Flow Summary**

1. **Input** → Multiple files of various types
2. **Classification** → AI determines format and processing path
3. **Routing** → Text files → JSON → YARA, Binary files → Direct YARA
4. **Processing** → Parallel execution of different paths
5. **Combination** → Merge all results into single outputs
6. **Validation** → LLM review and quality feedback
7. **Output** → Clean, combined YARA rules ready for use
8. **Cleanup** → Remove intermediate files, keep only final results

