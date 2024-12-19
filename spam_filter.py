import json
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailContent(BaseModel):
    content: str
    
class SpamFilterDFA:
    def __init__(self):
        # Define states
        self.states = {
            'start': 0,
            'money': 1,
            'urgent': 2,
            'offer': 3,
            'suspicious_link': 4,
            'spam': 5,
            'normal': 6
        }
        
        # Current state
        self.current_state = self.states['start']
        
        # Define suspicious patterns
        self.money_patterns = {'$', 'cash', 'money', 'dollars', 'earn', 'income'}
        self.urgent_patterns = {'urgent', 'immediate', 'act now', 'limited time', 'hurry'}
        self.offer_patterns = {'free', 'discount', 'offer', 'sale', 'deal', 'winner'}
        self.suspicious_links = {'.xyz', '.info', 'click here', 'bit.ly'}
        
        # Threshold for spam classification
        self.spam_threshold = 2
        self.pattern_count = 0
        
    def process_email(self, email_content):
        """
        Process email content and determine if it's spam
        Returns: (bool, str) - (is_spam, reason)
        """
        # Convert to lowercase for pattern matching
        email_content = email_content.lower()
        
        # Reset state and count for new email
        self.current_state = self.states['start']
        self.pattern_count = 0
        reasons = []
        
        # Check for money-related patterns
        if any(pattern in email_content for pattern in self.money_patterns):
            self.pattern_count += 1
            self.current_state = self.states['money']
            reasons.append("Contains money-related terms")
        
        # Check for urgency patterns
        if any(pattern in email_content for pattern in self.urgent_patterns):
            self.pattern_count += 1
            self.current_state = self.states['urgent']
            reasons.append("Contains urgency-related terms")
        
        # Check for offer patterns
        if any(pattern in email_content for pattern in self.offer_patterns):
            self.pattern_count += 1
            self.current_state = self.states['offer']
            reasons.append("Contains promotional offers")
        
        # Check for suspicious links
        if any(pattern in email_content for pattern in self.suspicious_links):
            self.pattern_count += 1
            self.current_state = self.states['suspicious_link']
            reasons.append("Contains suspicious links")
        
        # Determine final state
        if self.pattern_count >= self.spam_threshold:
            self.current_state = self.states['spam']
            return True, " and ".join(reasons)
        else:
            self.current_state = self.states['normal']
            return False, "Email appears legitimate"

    def is_current_state_spam(self):
        """Check if current state is classified as spam"""
        return self.current_state == self.states['spam']

def test_spam_filter():
    spam_filter = SpamFilterDFA()
    
    try:
        # Load test emails from JSON file
        with open('emails.json', 'r') as file:
            test_data = json.load(file)
            test_emails = test_data['emails']
        
        print("Testing Spam Filter:")
        print("-" * 50)
        
        correct_classifications = 0
        total_tests = len(test_emails)
        
        for email in test_emails:
            is_spam, reason = spam_filter.process_email(email['content'])
            expected_spam = email['expected_classification'] == 'spam'
            
            print(f"\nTest {email['id']}:")
            print(f"Email: {email['content']}")
            print(f"Expected: {email['expected_classification']}")
            print(f"Result: {'spam' if is_spam else 'normal'}")
            print(f"Reason: {reason}")
            
            if is_spam == expected_spam:
                correct_classifications += 1
            
            print("-" * 50)
            
        accuracy = (correct_classifications / total_tests) * 100
        print(f"\nAccuracy: {accuracy:.2f}%")
            
    except FileNotFoundError:
        print("Error: emails.json file not found. Please ensure it exists in the current directory.")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in emails.json file.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

spam_filter = SpamFilterDFA()

@app.post("/analyze")
async def analyze_email(email: EmailContent):
    is_spam, reason = spam_filter.process_email(email.content)
    return {"is_spam": is_spam, "reason": reason}