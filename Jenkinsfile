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

    stage('Redeploy ECS Services (force)') {
      steps {
        sh '''
          set -e
          CLUSTER="amznClassroom"
          for SVC in assignment-service-service-1feic8fz classroom-service-service-vhr17qym materials-service-service-gmwp0g6x submission-service-service-cg00q5gb; do
            aws ecs update-service --cluster "$CLUSTER" --service "$SVC" --force-new-deployment
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
    environment { UI_PORT = '5173' } // change if you want a different port
    steps {
        dir('classroom-spa') {
        sh '''
            set -euo pipefail
            CWD="$(pwd)"
            [ -d dist ] || { echo "dist/ missing; run Build SPA stage first"; exit 1; }

            # free the port if something is already listening
            fuser -k ${UI_PORT}/tcp || true

            # restart under PM2 (uses globally-installed http-server)
            pm2 delete classroom-spa || true
            pm2 start "http-server dist -p ${UI_PORT} -a 0.0.0.0 -s --cors" \
            --name classroom-spa --time --cwd "$CWD"
            pm2 save

            # quick health probe on localhost
            for i in $(seq 1 10); do
            curl -fsS "http://127.0.0.1:${UI_PORT}/" >/dev/null && break || sleep 1
            done
            echo "SPA listening on :${UI_PORT}"
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
