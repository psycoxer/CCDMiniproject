pipeline {
  agent any

  environment {
    AWS_REGION     = 'ap-south-1'
    AWS_ACCOUNT_ID = '412917579743'
    ECR_REGISTRY   = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    // folders = repo dirs; ECR repo names should already exist with the same names
    SERVICES       = "classroom-service assignment-service submission-service materials-service"
    UI_PORT        = "5173"
  }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('AWS ECR Login') {
      steps {
        // If you created AWS credentials in Jenkins (Option B), uncomment:
        // withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-jenkins']]) {
        sh '''
          set -e
          aws --version
          aws ecr get-login-password --region ${AWS_REGION} \
            | docker login --username AWS --password-stdin ${ECR_REGISTRY}
        '''
        // }
      }
    }

    stage('Build & Push Services') {
      steps {
        script {
          env.SHORT_SHA = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
        }
        sh '''
          set -euo pipefail
          for SVC in ${SERVICES}; do
            echo "=== Building $SVC ==="
            IMG=${ECR_REGISTRY}/$SVC:${SHORT_SHA}
            docker build -t $IMG $SVC
            docker tag $IMG ${ECR_REGISTRY}/$SVC:latest
            docker push $IMG
            docker push ${ECR_REGISTRY}/$SVC:latest
          done
        '''
      }
    }

    stage('Build SPA') {
      steps {
        dir('classroom-spa') {
          sh '''
            set -e
            npm ci || npm install
            npm run build
          '''
        }
      }
    }

    stage('Run SPA (pm2)') {
    steps {
        dir('classroom-spa') {
        sh '''
            set -e

            # ensure `serve` is available for jenkins user
            SERVE_BIN=$(command -v serve || true)
            if [ -z "$SERVE_BIN" ]; then
            npm i -g serve
            SERVE_BIN=$(command -v serve)
            fi

            # free the port if a leftover process is holding it (ignore errors)
            fuser -k 5173/tcp || true

            # restart under PM2
            pm2 delete classroom-spa || true
            pm2 start "$SERVE_BIN" --name classroom-spa -- -s dist -l tcp://0.0.0.0:${UI_PORT}
            pm2 save
            pm2 status classroom-spa
        '''
        }
    }
    }

  }

  post {
    success {
      echo "Build OK. Images tagged :${SHORT_SHA} and :latest. SPA restarted."
    }
    failure {
      echo "Build failed. Check the stage logs."
    }
  }
}
