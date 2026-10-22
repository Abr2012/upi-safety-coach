                "in your payment app before paying."
            ),
        },
        {
            "title": "Challenge 5: The Screen-Sharing Request",
            "message": (
                "A stranger claiming to be customer support asks you to "
                "install a remote-access app to fix a payment problem."
            ),
            "options": [
                "Install it immediately",
                "Give them control of your phone",
                "Decline and contact the payment provider through official support",
                "Tell them your UPI PIN first",
            ],
            "answer": 2,
            "explanation": (
                "Unverified remote-access requests can expose sensitive "
                "information or enable unauthorized actions. Use official "
                "support channels instead."
            ),
        },
    ]

    if "simulator_answers" not in st.session_state:
        st.session_state.simulator_answers = {}

    if "simulator_submitted" not in st.session_state:
        st.session_state.simulator_submitted = False

    with st.form("scam_simulator_form"):
        for i, scenario in enumerate(scenarios):
            st.markdown(f"### {scenario['title']}")
            st.warning(scenario["message"])

            selected = st.radio(
                "What is the safest response?",
                scenario["options"],
                key=f"simulator_question_{i}",
            )

            st.session_state.simulator_answers[i] = selected

            if i < len(scenarios) - 1:
                st.divider()

        submitted = st.form_submit_button(
            "Check my answers",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        st.session_state.simulator_submitted = True

        score = sum(
            st.session_state.simulator_answers.get(i)
            == scenario["options"][scenario["answer"]]
            for i, scenario in enumerate(scenarios)
        )

        st.session_state.simulator_score = score

        st.session_state.report_items.append({
            "type": "Scam Simulator",
            "input": "Five fictional UPI safety scenarios",
            "result": f"Score: {score}/{len(scenarios)}",
            "time": datetime.now().isoformat(timespec="seconds"),
        })

    if st.session_state.simulator_submitted:
        score = st.session_state.simulator_score

        st.divider()
        st.subheader("🏆 Your Results")
        st.metric("Final Score", f"{score}/{len(scenarios)}")

        if score == len(scenarios):
            st.success("Excellent! You identified every safest response.")
        elif score >= 3:
            st.success("Good work! Review the explanations to learn more.")
        else:
            st.info(
                "Keep practising! Read each explanation to strengthen "
                "your scam-awareness skills."
            )

        for i, scenario in enumerate(scenarios):
            chosen = st.session_state.simulator_answers.get(i)
            correct = scenario["options"][scenario["answer"]]

            if chosen == correct:
                st.success(f"{scenario['title']}: Correct answer")
            else:
                st.error(f"{scenario['title']}: Review your answer")

            st.markdown(f"**Safest response:** {correct}")
            st.write(scenario["explanation"])

        if st.button("🔄 Try Again", key="simulator_retry"):
            st.session_state.simulator_answers = {}
            st.session_state.simulator_submitted = False
            st.rerun()

    st.caption(
        "Educational simulation only. Scenarios are fictional and do not "
        "verify real messages, people, or transactions."
    )







