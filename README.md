# AI-PasswordAnalyzer
About the Project

This is a simple web app I built that checks the strength of passwords using a machine learning model. It gives users an idea of how secure their password is and offers suggestions to make it better. I created this project to learn how ML can be used in real-world applications like cybersecurity.

What It Does
	•	Analyzes passwords and gives a strength rating.
	•	Shows if the password is weak, average, or strong.
	•	Suggests ways to improve weak passwords.
	•	Has a clean and basic UI built using Flask templates.

Tech Stack
	•	Backend: Python, Flask
	•	Machine Learning: Trained model for password strength prediction
	•	Frontend: HTML, CSS (basic styling)
	•	Others: Jupyter Notebook (for model training), Pickle (to save the model)

Setup & Installation
	1.	Clone this repository:
 	2.	Install dependencies:pip install -r requirements.txt
  3.	Run the application: python app.py
  4.	Open your browser and go to http://127.0.0.1:5000/.

  Folder Structure
	•	app.py – Main Python file to start the Flask app
	•	ml_model/ – Contains the trained ML model
	•	templates/ – HTML pages (like index and result)
	•	static/ – CSS, images, or JS if needed
	•	models/ – Could include model code or training files
	•	requirements.txt – Python packages used

Why I Made This

I’ve always been interested in how machine learning can be used to improve online security. This was my small step to combine what I’m learning in ML with a basic web app. It helped me understand end-to-end integration—training a model, saving it, using it in a Flask app, and building a UI.
