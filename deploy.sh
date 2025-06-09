#!/bin/bash

# SOC Automation Bot Deployment Script
set -e

echo "🛡️  SOC Automation Bot Deployment Script"
echo "========================================"

# Function to print colored output
print_info() {
    echo -e "\033[36m[INFO]\033[0m $1"
}

print_success() {
    echo -e "\033[32m[SUCCESS]\033[0m $1"
}

print_error() {
    echo -e "\033[31m[ERROR]\033[0m $1"
}

print_warning() {
    echo -e "\033[33m[WARNING]\033[0m $1"
}

# Parse command line arguments
DEPLOY_MODE=${1:-"local"}
PORT=${2:-5000}

print_info "Deployment mode: $DEPLOY_MODE"
print_info "Dashboard port: $PORT"

# Create necessary directories
print_info "Creating directories..."
mkdir -p logs data models config

case $DEPLOY_MODE in
    "local")
        print_info "Starting local development deployment..."
        
        # Check if Python 3 is installed
        if ! command -v python3 &> /dev/null; then
            print_error "Python 3 is not installed. Please install Python 3.10 or later."
            exit 1
        fi
        
        # Create virtual environment if it doesn't exist
        if [ ! -d "venv" ]; then
            print_info "Creating virtual environment..."
            python3 -m venv venv
        fi
        
        # Activate virtual environment and install dependencies
        print_info "Installing dependencies..."
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
        
        # Run the application
        print_info "Starting SOC Automation Bot..."
        python main.py --mode continuous --port $PORT
        ;;
        
    "docker")
        print_info "Starting Docker deployment..."
        
        # Check if Docker is installed
        if ! command -v docker &> /dev/null; then
            print_error "Docker is not installed. Please install Docker first."
            exit 1
        fi
        
        # Build Docker image
        print_info "Building Docker image..."
        docker build -t soc-automation-bot .
        
        # Stop existing container if running
        if [ "$(docker ps -q -f name=soc-automation-bot)" ]; then
            print_info "Stopping existing container..."
            docker stop soc-automation-bot
            docker rm soc-automation-bot
        fi
        
        # Run new container
        print_info "Starting new container..."
        docker run -d \
            --name soc-automation-bot \
            -p $PORT:5000 \
            -v $(pwd)/logs:/app/logs \
            -v $(pwd)/data:/app/data \
            -v $(pwd)/models:/app/models \
            soc-automation-bot
        
        print_success "Container started successfully!"
        print_info "Dashboard URL: http://localhost:$PORT"
        print_info "View logs: docker logs -f soc-automation-bot"
        ;;
        
    "docker-compose")
        print_info "Starting Docker Compose deployment..."
        
        # Check if Docker Compose is installed
        if ! command -v docker-compose &> /dev/null; then
            print_error "Docker Compose is not installed. Please install Docker Compose first."
            exit 1
        fi
        
        # Update port in docker-compose.yml if different from 5000
        if [ "$PORT" != "5000" ]; then
            print_info "Updating port in docker-compose.yml..."
            sed -i.bak "s/5000:5000/$PORT:5000/g" docker-compose.yml
        fi
        
        # Stop existing services
        print_info "Stopping existing services..."
        docker-compose down || true
        
        # Start services
        print_info "Starting services with Docker Compose..."
        docker-compose up -d --build
        
        print_success "Services started successfully!"
        print_info "Dashboard URL: http://localhost:$PORT"
        print_info "View logs: docker-compose logs -f"
        ;;
        
    "test")
        print_info "Running test mode..."
        
        # Create virtual environment if it doesn't exist
        if [ ! -d "venv" ]; then
            print_info "Creating virtual environment..."
            python3 -m venv venv
        fi
        
        # Activate virtual environment and install dependencies
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
        
        # Run once to test
        print_info "Running pipeline test..."
        python main.py --mode once
        
        print_success "Test completed successfully!"
        ;;
        
    *)
        print_error "Unknown deployment mode: $DEPLOY_MODE"
        echo "Usage: $0 [local|docker|docker-compose|test] [port]"
        echo ""
        echo "Deployment modes:"
        echo "  local           - Run locally with Python virtual environment"
        echo "  docker          - Run in Docker container"
        echo "  docker-compose  - Run with Docker Compose"
        echo "  test            - Run pipeline once for testing"
        echo ""
        echo "Examples:"
        echo "  $0 local 8080"
        echo "  $0 docker"
        echo "  $0 docker-compose 5000"
        echo "  $0 test"
        exit 1
        ;;
esac

print_success "Deployment completed! 🎉"

# Display useful information
echo ""
echo "📊 SOC Automation Bot Information:"
echo "=================================="
echo "🌐 Dashboard URL: http://localhost:$PORT"
echo "📁 Logs Directory: $(pwd)/logs"
echo "💾 Data Directory: $(pwd)/data" 
echo "🤖 Models Directory: $(pwd)/models"
echo ""
echo "🔧 Management Commands:"
case $DEPLOY_MODE in
    "docker")
        echo "  View logs:     docker logs -f soc-automation-bot"
        echo "  Stop service:  docker stop soc-automation-bot"
        echo "  Start service: docker start soc-automation-bot"
        echo "  Remove:        docker rm -f soc-automation-bot"
        ;;
    "docker-compose")
        echo "  View logs:     docker-compose logs -f"
        echo "  Stop services: docker-compose down"
        echo "  Start services: docker-compose up -d"
        echo "  Rebuild:       docker-compose up -d --build"
        ;;
    "local")
        echo "  Stop service:  Ctrl+C"
        echo "  Activate venv: source venv/bin/activate"
        echo "  Run dashboard: python main.py --mode dashboard --port $PORT"
        ;;
esac
echo ""
print_warning "Remember to customize configuration in soc_config.json for production use!" 