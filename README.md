# Basic_flask


# Environment setup
python3 -m venv venv
source venv/bin/activate

# Database initialization 
 pip install Flask-Migrate 
 from flask_migrate import Migrate

 # after creating the app 

 migrate = Migrate(app, db) 
 
 flask db init
 flask db migrate -m "initial migration"
 flask db upgrade

  # To run the server

    export FLASK_APP=main.py
    export FLASK_ENV=development
    flask run
