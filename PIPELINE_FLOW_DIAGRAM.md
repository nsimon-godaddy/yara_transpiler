# YARA Pipeline Flow Diagram

## 📋 Quick Navigation

- **[🚀 Complete Pipeline Architecture](#-complete-pipeline-architecture)** - Full visual flow diagram
- **[🔄 Detailed Process Flow](#-detailed-process-flow)** - Step-by-step breakdown
- **[🎯 Key Components & Functions](#-key-components--their-functions)** - Component descriptions
- **[🔧 Technical Implementation](#-technical-implementation-details)** - Code examples
- **[📊 Data Flow Summary](#-data-flow-summary)** - Simplified data flow
- **[🎉 Benefits & Future](#-benefits-of-current-architecture)** - Advantages and roadmap

## 🚀 Complete Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           YARA PIPELINE RUNNER                                    │
│                              (run_pipeline.sh)                                    │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        ENVIRONMENT & PREREQUISITES CHECK                           │
│  • Load .env file (JWT, API_URL)                                                 │
│  • Verify Python scripts exist                                                   │
│  • Check input file availability                                                 │
│  • Validate file permissions                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              STEP 1: FILE PROCESSING                              │
│  • Process multiple input files (text + binary)                                  │
│  • Route files based on extension (.txt vs others)                              │
│  • Handle both single and batch file processing                                  │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
                    ┌───────────────────┴───────────────────┐
                    │                                       │
                    ▼                                       ▼
        ┌─────────────────────┐                 ┌─────────────────────┐
        │    TEXT FILES       │                 │   BINARY FILES      │
        │   (.txt only)       │                 │   (.php, .exe, etc) │
        └─────────────────────┘                 └─────────────────────┘
                    │                                       │
                    ▼                                       ▼
        ┌─────────────────────┐                 ┌─────────────────────┐
        │  txt_to_json.py     │                 │ PROMPT OPTIMIZATION │
        │  • Parse signature  │                 │      LAYER          │
        │    patterns         │                 │  • Analyze file     │
        │  • Extract cleanup  │                 │    characteristics  │
        │    constants        │                 │  • Generate        │
        │  • Convert to JSON  │                 │    optimized       │
        │  • Handle           │                 │    prompts         │
        │    duplicates       │                 │  • Route to        │
        └─────────────────────┘                 │    appropriate     │
                    │                           │    template        │
                    ▼                           └─────────────────────┘
        ┌─────────────────────┐                           │
        │  signatures.json    │                           ▼
        │  • Structured       │                 ┌─────────────────────┐
        │    signature data   │                 │   DATA CLASSIFIER   │
        │  • Cleanup          │                 │      LAYER          │
        │    constants        │                 │  • Load file        │
        │  • Triggers &       │                 │    content          │
        │    full chains      │                 │  • PHP Content      │
        └─────────────────────┘                 │    Filtering:       │
                                                │    • Remove echo/    │
                                                │      print docs     │
                                                │    • Remove HTML/    │
                                                │      comments       │
                                                │    • Focus on       │
                                                │      actual code     │
                                                │  • Base64 encode    │
                                                │    for LLM          │
                                                │  • Send to Gocaas   │
                                                │    API with         │
                                                │    optimized        │
                                                │    prompts          │
                                                └─────────────────────┘
                                                        │
                                                        ▼
                                        ┌─────────────────────────────┐
                                        │      LLM PROCESSING        │
                                        │   (Gocaas API)             │
                                        │  • Claude 3.5 Haiku        │
                                        │  • Code-focused prompts    │
                                        │  • Example-based learning  │
                                        │  • Behavior detection      │
                                        │  • Avoid text patterns     │
                                        └─────────────────────────────┘
                                                        │
                                                        ▼
                                        ┌─────────────────────────────┐
                                        │    YARA RULE EXTRACTION    │
                                        │  • Parse LLM response      │
                                        │  • Extract YARA rules      │
                                        │  • Validate syntax         │
                                        │  • Handle multiple rules   │
                                        │  • Rule deduplication      │
                                        └─────────────────────────────┘
                                                        │
                                                        ▼
                                        ┌─────────────────────────────┐
                                        │   BINARY FILE RULES        │
                                        │  • PHP webshell rules      │
                                        │  • Executable malware      │
                                        │  • Script backdoors        │
                                        │  • Archive payloads        │
                                        └─────────────────────────────┘
                    │                                       │
                    └───────────────────┬───────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              STEP 2: YARA GENERATION                               │
│  • Combine text file JSON + binary file rules                                     │
│  • Run transpile_to_yara.py                                                       │
│  • Generate final yara_rules.yar                                                  │
│  • Append binary file rules to output                                             │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              STEP 3: VALIDATION                                   │
│  • Verify JSON file creation                                                      │
│  • Verify YARA file creation                                                      │
│  • Count signatures and rules                                                     │
│  • Log success/failure metrics                                                    │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────┘
│                              OUTPUT FILES                                          │
│  • data/signatures.json - Text file signatures                                    │
│  • data/yara_rules.yar - Combined YARA rules                                      │
│  • classification_*.json - LLM classification results                             │
│  • prompt_optimization_*.json - Optimized prompts                                 │
│  • *.log - Pipeline execution logs                                                │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 🔄 Detailed Process Flow

### **Phase 1: Input Processing & Classification**
```
Input Files → File Type Detection → Routing Decision
     │
     ├── .txt files → txt_to_json.py → JSON signatures
     │
     └── Binary files → Prompt Optimization → Data Classification → LLM Processing
```

### **Phase 2: Prompt Optimization Layer**
```
Binary File → File Analysis → Template Selection → Prompt Generation
     │
     ├── executable → Executable template
     ├── script → Script template (PHP-focused)
     ├── document → Document template
     ├── archive → Archive template
     └── default → Generic template
```

### **Phase 3: Data Classification & LLM Processing**
```
Optimized Prompt + File Content → Gocaas API → YARA Rule Generation
     │
     ├── PHP Content Filtering:
     │   • Remove echo/print statements
     │   • Remove HTML/comments
     │   • Focus on actual code
     │
     ├── LLM Processing:
     │   • Code behavior analysis
     │   • Function call detection
     │   • Execution pattern identification
     │   • Example-based learning
     │
     └── Rule Extraction:
         • Parse LLM response
         • Extract YARA syntax
         • Validate rule structure
```

### **Phase 4: Rule Generation & Combination**
```
Text Signatures + Binary Rules → Transpilation → Final YARA File
     │
     ├── JSON Processing:
     │   • Load signatures.json
     │   • Parse cleanup constants
     │   • Generate YARA rules
     │
     ├── Binary Rule Integration:
     │   • Append LLM-generated rules
     │   • Handle rule deduplication
     │   • Maintain rule naming
     │
     └── Output Generation:
         • Create yara_rules.yar
         • Include all rule types
         • Validate final output
```

## 🎯 Key Components & Their Functions

### **1. Prompt Optimization Layer (`prompt_optimizer.py`)**
- **Purpose**: Generate context-aware prompts for different file types
- **Input**: File content analysis (extension, type, characteristics)
- **Output**: Optimized prompts with examples and constraints
- **Templates**: Executable, script, document, archive, text, default

### **2. Data Classification Layer (`data_classifier.py`)**
- **Purpose**: Route files to appropriate processing and handle LLM communication
- **Input**: File content + optimized prompts
- **Output**: LLM classification results with YARA rules
- **Features**: PHP content filtering, base64 encoding, API integration

### **3. LLM Integration (Gocaas API)**
- **Model**: Claude 3.5 Haiku
- **Purpose**: Generate YARA rules based on file analysis
- **Input**: Optimized prompts + file content
- **Output**: Structured YARA rules with proper syntax
- **Learning**: Example-based prompts for consistent quality

### **4. Content Filtering (PHP-specific)**
- **Purpose**: Remove documentation and focus on actual code
- **Filters**: echo/print statements, HTML comments, documentation text
- **Keeps**: Function calls, variable usage, execution patterns
- **Output**: Clean, code-focused content for LLM analysis

### **5. Rule Generation & Combination**
- **Text Files**: Structured JSON → YARA rules via transpile_to_yara.py
- **Binary Files**: LLM-generated rules with behavior focus
- **Combination**: Merge both rule types into final output
- **Output**: Comprehensive yara_rules.yar file

## 🔧 Technical Implementation Details

### **File Type Detection**
```python
if file_extension == '.txt':
    # Route to txt_to_json.py
    # Generate structured JSON signatures
else:
    # Route to prompt optimization
    # Generate LLM-focused prompts
```

### **PHP Content Filtering**
```python
def _filter_php_content(binary_data: bytes) -> bytes:
    # Remove echo/print statements (documentation)
    # Remove HTML comments and tags
    # Keep actual PHP code patterns
    # Focus on execution behavior
```

### **Prompt Optimization**
```python
def _load_prompt_templates(self) -> Dict[str, str]:
    # File type-specific templates
    # Include examples and constraints
    # Focus on behavior over text
    # Avoid common pitfalls
```

### **LLM Integration**
```python
# Gocaas API configuration
api_config = {
    "isPrivate": True,
    "provider": "anthropic_chat",
    "providerOptions": {
        "model": "claude-3-5-haiku-20241022-v1:0",
        "max_tokens": 2048
    }
}
```

## 📊 Data Flow Summary

```
Input Files
    │
    ├── Text Files (.txt)
    │   └── → JSON Signatures → YARA Rules
    │
    └── Binary Files (.php, .exe, etc.)
        ├── → Prompt Optimization
        ├── → Content Filtering
        ├── → LLM Processing
        ├── → YARA Rule Generation
        └── → Rule Combination
            │
            └── → Final YARA Output
```

## 🎉 Benefits of Current Architecture

1. **Intelligent Routing**: Automatically routes files to appropriate processors
2. **Content Filtering**: Removes noise and focuses on actual malicious behavior
3. **Example-Based Learning**: LLM learns from high-quality examples
4. **Behavior Focus**: Detects what malware DOES, not what it SAYS
5. **Scalable Processing**: Handles multiple file types and batch processing
6. **Quality Assurance**: Consistent rule structure and syntax
7. **False Positive Reduction**: Multiple condition requirements and file type validation

## 🔮 Future Enhancements

- **Additional File Types**: Support for more malware categories
- **Enhanced Filtering**: More sophisticated content analysis
- **Rule Validation**: YARA syntax checking and optimization
- **Performance Metrics**: Processing time and success rate tracking
- **Integration APIs**: Connect with other security tools and platforms
