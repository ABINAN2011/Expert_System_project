import os
from groq import Groq
from dotenv import load_dotenv


load_dotenv()


GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("❌ GROQ_API_KEY not found! Please set it in your .env file or environment variables.")

client = Groq(api_key=GROQ_API_KEY)


AVAILABLE_MODELS = [
    "llama-3.3-70b-versatile",      
    "llama-3.2-11b-vision-preview", 
    "mixtral-8x7b-32768",           
    "gemma-7b-it",                  
]

def get_available_model():
    """
    Attempts to find the first available model from the list.
    Returns the first working model or raises an error if none are available.
    """
    for model in AVAILABLE_MODELS:
        try:
           
            client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1
            )
            print(f"✅ Using Groq model: {model}")
            return model
        except Exception as e:
            if "decommissioned" in str(e) or "not found" in str(e):
                continue
            else:
                raise
    
    raise ValueError(f"❌ No available Groq models found. Tried: {AVAILABLE_MODELS}")


ACTIVE_MODEL = get_available_model()

def generate_threat_summary(report):
    """
    Use Groq LLM to analyze the expert system report
    and generate a human-readable summary.
    """
    prompt = f"""
    You are a cybersecurity analyst. Analyze this threat report:

    {report}

    Please provide:
    1. A brief summary of what likely happened.
    2. Possible attack vector.
    3. Immediate next steps.
    4. Preventive recommendations.
    """

    completion = client.chat.completions.create(
        model=ACTIVE_MODEL,
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.4,
        max_tokens=400
    )

    return completion.choices[0].message.content.strip()
