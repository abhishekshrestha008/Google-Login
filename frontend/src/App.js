import "./App.css";
import { GoogleLogin } from "@react-oauth/google";
import axios from "axios";

function App() {
  const responseMessage = (response) => {
    console.log(response.credential);
    axios
      .post("http://localhost:8080/auth/google", {
        token: response.credential,
      })
      .then((res) => {
        console.log("hello", res.data);
      })
      .catch((err) => console.log(err));
  };
  const errorMessage = (error) => {
    console.log(error);
  };

  return (
    <div>
      <h2>React Google Login</h2>
      <br />
      <br />
      <GoogleLogin onSuccess={responseMessage} onError={errorMessage} />
    </div>
  );
}

export default App;
