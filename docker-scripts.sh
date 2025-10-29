# Docker scripts for SecureApp

#!/bin/bash

# Build and run SecureApp with Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_status "Docker and Docker Compose are available"
}

# Build the application
build_app() {
    print_status "Building SecureApp Docker image..."
    docker build -t secureapp:latest .
    print_status "Build completed successfully"
}

# Run in development mode
run_dev() {
    print_status "Starting SecureApp in development mode..."
    docker-compose -f docker-compose.dev.yml --profile dev up --build
}

# Run in production mode
run_prod() {
    print_status "Starting SecureApp in production mode..."
    docker-compose -f docker-compose.prod.yml up -d --build
}

# Run tests
run_tests() {
    print_status "Running SecureApp tests..."
    docker-compose -f docker-compose.dev.yml --profile test up --build --abort-on-container-exit
}

# Run linting
run_lint() {
    print_status "Running SecureApp linting..."
    docker-compose -f docker-compose.dev.yml --profile lint up --build --abort-on-container-exit
}

# Stop all containers
stop_all() {
    print_status "Stopping all SecureApp containers..."
    docker-compose -f docker-compose.yml down
    docker-compose -f docker-compose.dev.yml down
    docker-compose -f docker-compose.prod.yml down
    print_status "All containers stopped"
}

# Clean up Docker resources
cleanup() {
    print_status "Cleaning up Docker resources..."
    docker system prune -f
    docker volume prune -f
    print_status "Cleanup completed"
}

# Show logs
show_logs() {
    print_status "Showing SecureApp logs..."
    docker-compose -f docker-compose.yml logs -f
}

# Show help
show_help() {
    echo "SecureApp Docker Management Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build     Build the Docker image"
    echo "  dev       Run in development mode"
    echo "  prod      Run in production mode"
    echo "  test      Run tests"
    echo "  lint      Run linting"
    echo "  stop      Stop all containers"
    echo "  logs      Show application logs"
    echo "  cleanup   Clean up Docker resources"
    echo "  help      Show this help message"
    echo ""
}

# Main script logic
main() {
    check_docker
    
    case "${1:-help}" in
        build)
            build_app
            ;;
        dev)
            run_dev
            ;;
        prod)
            run_prod
            ;;
        test)
            run_tests
            ;;
        lint)
            run_lint
            ;;
        stop)
            stop_all
            ;;
        logs)
            show_logs
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
