import axios from "axios";
import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";

const Forgot = () => {
  const [form, setForm] = useState({});
  const { id } = useParams();
  const navigate = useNavigate();

  const handleVerify = async () => {
    try {
      const data = await axios.post(
        `http://localhost:8080/forgotpassword/${id}`
      );
      if (!data.data) {
        navigate("/signup");
      }
      console.log(data.data, "kkf");
    } catch (e) {
      console.log(e);
      navigate("/signup");
    }
  };

  const handleUpdate = async (e) => {
    e.preventDefault();
    alert("came");
    if (form.password != form.confirmPassword) {
      return alert("passwords not matched");
    }

    try {
      const data = await axios.post(
        "http://localhost:8080/forgotpassword/reset",
        {
          ...form,
          token: id,
        }
      );

      if (data.data) {
        alert(data.data);
        navigate("/login");
      }
    } catch (e) {
      console.log(e);
      alert("something");
    }
  };

  useEffect(() => {
    handleVerify();
  }, []);

  return (
    <div class="w-full max-w-sm mx-auto overflow-hidden bg-white rounded-lg shadow-md dark:bg-gray-800">
      <div class="px-6 py-4">
        <h2 class="text-3xl font-bold text-center text-gray-700 dark:text-white">
          E-connect
        </h2>

        <h3 class="mt-1 text-xl font-medium text-center text-gray-600 dark:text-gray-200"></h3>

        <p class="mt-1 text-center text-gray-500 dark:text-gray-400">
          Please Reset Your Passsword
        </p>

        <div class="w-full mt-4">
          <input
            onChange={(e) =>
              setForm({ ...form, [e.target.name]: e.target.value })
            }
            class="block w-full px-4 py-2 mt-2 text-gray-700 placeholder-gray-500 bg-white border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:placeholder-gray-400 focus:border-blue-400 dark:focus:border-blue-300 focus:ring-opacity-40 focus:outline-none focus:ring focus:ring-blue-300"
            type="password"
            placeholder="Enter Your Password"
            aria-label="Email Address"
            name="password"
          />
        </div>

        <div class="w-full mt-4">
          <input
            onChange={(e) =>
              setForm({ ...form, [e.target.name]: e.target.value })
            }
            class="block w-full px-4 py-2 mt-2 text-gray-700 placeholder-gray-500 bg-white border rounded-md dark:bg-gray-800 dark:border-gray-600 dark:placeholder-gray-400 focus:border-blue-400 dark:focus:border-blue-300 focus:ring-opacity-40 focus:outline-none focus:ring focus:ring-blue-300"
            type="password"
            placeholder="Confirm Password"
            aria-label="Password"
            name="confirmPassword"
          />
        </div>

        <div class="flex items-center justify-between mt-4">
          <button
            onClick={handleUpdate}
            class="px-4 py-2 leading-5 text-white transition-colors duration-200 transform bg-gray-700 rounded hover:bg-gray-600 focus:outline-none"
            type="button"
          >
            Reset Password
          </button>
        </div>
      </div>
    </div>
  );
};

export default Forgot;
