#!/usr/bin/env groovy

pipeline {
  agent any
    stages {
      stage('Build') {
        steps {
          checkout scm
          sh 'mvn clean package deploy'
        }
      }
    }
}
