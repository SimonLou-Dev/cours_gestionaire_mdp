import axios from "axios";



const apiClient = axios.create({
  baseURL: "http://localhost:8000",
  headers: {
    'Content-Type': 'application/json',
    // You can add other headers like authorization token here
  },
});

export default apiClient;