pipeline {
    agent any

    environment {
        APP_NAME = 'sentinelscan-api'
        IMAGE_NAME = "sentinelscan-api:${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh 'npm ci'
            }
        }

        stage('Generate Prisma Client') {
            steps {
                sh 'npx prisma generate'
            }
        }

        stage('Lint') {
            steps {
                sh 'npm run lint'
            }
        }

        stage('Typecheck') {
            steps {
                sh 'npm run typecheck'
            }
        }

        stage('Test') {
            steps {
                sh 'npm test'
            }
        }

        stage('Build') {
            steps {
                sh 'npm run build'
            }
        }

        stage('Security Scan') {
            steps {
                // Placeholder: CI security stage for future SAST / dependency auditing (e.g. npm audit)
                echo 'Security Scan placeholder stage - to be configured in a future stage.'
            }
        }

        stage('Container Scan') {
            steps {
                // Placeholder: Container vulnerability scanning (e.g. Trivy)
                echo 'Container Scan placeholder stage - to be configured in a future stage.'
            }
        }

        stage('Docker Build') {
            steps {
                sh "docker build -t ${IMAGE_NAME} ."
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo 'SentinelScan API CI Pipeline completed successfully.'
        }
        failure {
            echo 'SentinelScan API CI Pipeline failed.'
        }
    }
}
