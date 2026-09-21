#!/usr/bin/env groovy

pipeline {
  agent any
  environment {
    JAVA_HOME = '/usr/lib/jvm/temurin-8-jdk-amd64'
  }
  stages {
    stage('Build') {
      steps {
        checkout scm
        sh 'mvn clean package deploy'
      }
    }
  }
}
