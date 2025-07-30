# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Install Flask and Werkzeug
RUN pip install --no-cache-dir Flask Werkzeug

# Copy the application code into the container
COPY app.py .
COPY templates/ templates/

# Expose the port the app runs on
EXPOSE 5000

# Run the application
# Use exec form to allow Docker to handle signals properly
CMD ["python3", "app.py"]