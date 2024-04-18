#!/usr/bin/env groovy

pipeline {
  agent any
    stages {
      stage('Build') {
        steps {
          checkout scm
          sh 'mvn clean package deploy:deploy-file -DgroupId=com.opendigitaleducation -DartifactId=oauth2-server  -Durl=https://maven.opendigitaleducation.com/nexus/content/repositories/$nexusRepository/'
        }
      }
    }
}
